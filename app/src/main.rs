#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod export;
mod process_icon;
mod protocol;
mod source;

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use protocol::{
    ALL_CATEGORIES, CATEGORIES, DriverConfig, DriverStats, MAX_SYSCALLS, MAX_TARGET_NAMES,
    MAX_TARGET_PIDS, OPERATION_MASK_WORDS, PROCESS_NAME_BYTES, RawEvent, UNKNOWN_RESULT,
};
use source::{SourceCommand, SourceHandle, SourceMessage};
use sysinfo::System;

const ESTIMATED_BYTES_PER_EVENT: usize = 176;
const DEFAULT_EXCLUDED_OPERATION: &str = "NtDeviceIoControlFile";

#[derive(Clone)]
struct ProcessRow {
    pid: u32,
    parent: u32,
    name: String,
    path: String,
    running: bool,
    icon: Option<egui::TextureHandle>,
}

#[derive(Clone, Copy, PartialEq)]
enum View {
    Events,
    Processes,
    Statistics,
}

#[derive(Clone, Copy)]
enum ExportFormat {
    Csv,
    Jsonl,
    Txt,
}

enum OperationFilterAction {
    Include(String),
    Exclude(String),
    Clear(String),
}

struct EventMenuContext<'a> {
    names: &'a [String],
    details: &'a HashMap<u64, String>,
    outcomes: &'a HashMap<u64, String>,
    processes: &'a [ProcessRow],
    included_operations: &'a HashSet<String>,
    excluded_operations: &'a HashSet<String>,
    operation_action: &'a mut Option<OperationFilterAction>,
}

impl ExportFormat {
    fn extension(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Jsonl => "jsonl",
            Self::Txt => "txt",
        }
    }
}

struct MonitorApp {
    source: SourceHandle,
    events: Vec<RawEvent>,
    visible: Vec<usize>,
    syscall_names: Vec<String>,
    details: HashMap<u64, String>,
    outcomes: HashMap<u64, String>,
    category_counts: [u64; 10],
    stats: DriverStats,
    status: String,
    capture: bool,
    category_mask: u32,
    included_operations: HashSet<String>,
    excluded_operations: HashSet<String>,
    operation_filter_input: String,
    operation_filter_status: String,
    capture_process_text: String,
    active_capture_pids: Vec<u32>,
    active_capture_names: Vec<String>,
    search: String,
    process_filter: String,
    tid_filter: String,
    selected: Option<usize>,
    view: View,
    max_events: usize,
    history_evicted: u64,
    export_path: String,
    export_status: String,
    filters_dirty: bool,
    dark_mode: bool,
    default_process_icon: egui::TextureHandle,
    processes: Vec<ProcessRow>,
    last_process_refresh: Instant,
}

impl MonitorApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_theme(&cc.egui_ctx, true);
        let memory_probe = System::new_all();
        let default_max_events = recommended_event_limit(memory_probe.available_memory());
        let default_process_icon = load_default_process_icon(&cc.egui_ctx);
        let mut app = Self {
            source: SourceHandle::spawn(),
            events: Vec::with_capacity(default_max_events),
            visible: Vec::with_capacity(default_max_events),
            syscall_names: vec![String::new(); MAX_SYSCALLS],
            details: HashMap::new(),
            outcomes: HashMap::new(),
            category_counts: [0; 10],
            stats: DriverStats::default(),
            status: "Connecting…".into(),
            capture: true,
            category_mask: ALL_CATEGORIES,
            included_operations: HashSet::new(),
            excluded_operations: HashSet::from([DEFAULT_EXCLUDED_OPERATION.to_owned()]),
            operation_filter_input: String::new(),
            operation_filter_status: String::new(),
            capture_process_text: String::new(),
            active_capture_pids: Vec::new(),
            active_capture_names: Vec::new(),
            search: String::new(),
            process_filter: String::new(),
            tid_filter: String::new(),
            selected: None,
            view: View::Events,
            max_events: default_max_events,
            history_evicted: 0,
            export_path: "syscalls".into(),
            export_status: String::new(),
            filters_dirty: true,
            dark_mode: true,
            default_process_icon,
            processes: Vec::new(),
            last_process_refresh: Instant::now(),
        };
        app.refresh_processes(&cc.egui_ctx);
        app.send_config();
        app
    }

    fn send_config(&self) {
        let mut target_pids = [0_u32; MAX_TARGET_PIDS];
        let pid_count = self.active_capture_pids.len().min(MAX_TARGET_PIDS);
        target_pids[..pid_count].copy_from_slice(&self.active_capture_pids[..pid_count]);
        let mut target_names = [[0_u8; PROCESS_NAME_BYTES]; MAX_TARGET_NAMES];
        let name_count = self.active_capture_names.len().min(MAX_TARGET_NAMES);
        for (output, name) in target_names
            .iter_mut()
            .zip(self.active_capture_names.iter())
            .take(name_count)
        {
            *output = encode_kernel_process_name(name);
        }
        let _ = self
            .source
            .commands
            .send(SourceCommand::Configure(Box::new(DriverConfig {
                version: protocol::PROTOCOL_VERSION,
                category_mask: self.category_mask,
                capture_enabled: self.capture as u32,
                excluded_pid: std::process::id(),
                target_pid_count: pid_count as u32,
                target_pids,
                target_name_count: name_count as u32,
                target_names,
                operation_mask: self.operation_mask(),
            })));
    }

    fn operation_mask(&self) -> [u32; OPERATION_MASK_WORDS] {
        let mut mask = if self.included_operations.is_empty() {
            [u32::MAX; OPERATION_MASK_WORDS]
        } else {
            [0; OPERATION_MASK_WORDS]
        };
        for (id, name) in self.syscall_names.iter().enumerate() {
            if name.is_empty() {
                continue;
            }
            let enabled = !self.excluded_operations.contains(name)
                && (self.included_operations.is_empty() || self.included_operations.contains(name));
            if enabled {
                mask[id / 32] |= 1 << (id % 32);
            } else {
                mask[id / 32] &= !(1 << (id % 32));
            }
        }
        mask
    }

    fn operation_enabled(&self, name: &str) -> bool {
        !self.excluded_operations.contains(name)
            && (self.included_operations.is_empty() || self.included_operations.contains(name))
    }

    fn apply_operation_filter(&mut self, action: OperationFilterAction) {
        match action {
            OperationFilterAction::Include(name) => {
                self.excluded_operations.remove(&name);
                self.included_operations.insert(name);
            }
            OperationFilterAction::Exclude(name) => {
                self.included_operations.remove(&name);
                self.excluded_operations.insert(name);
            }
            OperationFilterAction::Clear(name) => {
                self.included_operations.remove(&name);
                self.excluded_operations.remove(&name);
            }
        }
        self.filters_dirty = true;
        self.send_config();
    }

    fn drain_source(&mut self) {
        for _ in 0..128 {
            let Ok(message) = self.source.messages.try_recv() else {
                break;
            };
            match message {
                SourceMessage::Status(status) => self.status = status,
                SourceMessage::Stats(stats) => self.stats = stats,
                SourceMessage::Details(details) => {
                    for (sequence, kind, detail) in details {
                        if kind == 1 {
                            self.outcomes.insert(sequence, detail);
                        } else {
                            self.details.insert(sequence, detail);
                        }
                    }
                    trim_auxiliary_map(&mut self.details, self.max_events);
                    trim_auxiliary_map(&mut self.outcomes, self.max_events);
                    self.filters_dirty |= !self.search.is_empty();
                }
                SourceMessage::SyscallTable(table) => {
                    for (id, _, name) in table {
                        if let Some(slot) = self.syscall_names.get_mut(id as usize) {
                            *slot = name;
                        }
                    }
                    self.filters_dirty = true;
                    self.send_config();
                }
                SourceMessage::Events(batch) => self.push_events(batch),
            }
        }
        if self.filters_dirty {
            self.rebuild_visible();
        }
    }

    fn push_events(&mut self, batch: Vec<RawEvent>) {
        for event in batch {
            let operation = export::name_for(&self.syscall_names, event.syscall_id);
            if !self.operation_enabled(operation) {
                continue;
            }
            if let Some(count) = self.category_counts.get_mut(event.category as usize) {
                *count += 1;
            }
            self.events.push(event);
        }
        if self.events.len() > self.max_events {
            let remove = self.events.len() - self.max_events;
            self.events.drain(..remove);
            self.history_evicted += remove as u64;
            self.selected = None;
        }
        if let Some(first) = self.events.first() {
            self.details
                .retain(|sequence, _| *sequence >= first.sequence);
            self.outcomes
                .retain(|sequence, _| *sequence >= first.sequence);
        }
        self.filters_dirty = true;
    }

    fn rebuild_visible(&mut self) {
        self.visible.clear();
        let search = self.search.trim().to_ascii_lowercase();
        let process_filter = self.process_filter.trim().to_ascii_lowercase();
        let tid = self.tid_filter.trim().parse::<u32>().ok();
        for (index, event) in self.events.iter().enumerate() {
            let Some(category_bit) = 1_u32.checked_shl(u32::from(event.category)) else {
                continue;
            };
            if self.category_mask & category_bit == 0 {
                continue;
            }
            if tid.is_some_and(|wanted| event.tid != wanted) {
                continue;
            }
            let name = export::name_for(&self.syscall_names, event.syscall_id);
            if !self.operation_enabled(name) {
                continue;
            }
            let process_name = event_process_name(event, &self.processes);
            let detail = self
                .details
                .get(&event.sequence)
                .cloned()
                .unwrap_or_else(|| event.display_arguments(name));
            if !process_filter.is_empty()
                && !process_name.to_ascii_lowercase().contains(&process_filter)
            {
                continue;
            }
            if !search.is_empty()
                && !name.to_ascii_lowercase().contains(&search)
                && !event.pid.to_string().contains(&search)
                && !process_name.to_ascii_lowercase().contains(&search)
                && !detail.to_ascii_lowercase().contains(&search)
            {
                continue;
            }
            self.visible.push(index);
        }
        self.filters_dirty = false;
    }

    fn refresh_processes(&mut self, ctx: &egui::Context) {
        let old_processes = self.processes.clone();
        let old_icons: HashMap<String, egui::TextureHandle> = self
            .processes
            .iter()
            .filter_map(|process| {
                process
                    .icon
                    .clone()
                    .map(|icon| (process.path.clone(), icon))
            })
            .collect();
        let mut system = System::new_all();
        system.refresh_all();
        self.processes = system
            .processes()
            .iter()
            .map(|(pid, process)| {
                let path = process
                    .exe()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default();
                let icon = old_icons.get(&path).cloned().or_else(|| {
                    process_icon::load(&path).map(|image| {
                        ctx.load_texture(
                            format!("process-icon-{}", pid.as_u32()),
                            image,
                            egui::TextureOptions::LINEAR,
                        )
                    })
                });
                ProcessRow {
                    pid: pid.as_u32(),
                    parent: process.parent().map_or(0, |parent| parent.as_u32()),
                    name: process.name().to_string_lossy().into_owned(),
                    path,
                    running: true,
                    icon,
                }
            })
            .collect();
        let retained_pids: HashSet<u32> = self.events.iter().map(|event| event.pid).collect();
        for mut process in old_processes {
            if retained_pids.contains(&process.pid)
                && !self
                    .processes
                    .iter()
                    .any(|current| current.pid == process.pid)
            {
                process.running = false;
                self.processes.push(process);
            }
        }
        self.processes.sort_by(|a, b| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
        });
        self.last_process_refresh = Instant::now();
    }

    fn apply_capture_process(&mut self) {
        let (pids, names) = parse_capture_filters(&self.capture_process_text);
        self.active_capture_pids = pids;
        self.active_capture_names = names;
        self.prune_history_to_capture();
        self.status = match (
            self.active_capture_pids.len(),
            self.active_capture_names.len(),
        ) {
            (0, 0) => "Capturing all processes".into(),
            (pids, 0) => format!("Capturing {pids} caller PID(s)"),
            (0, names) => format!("Capturing {names} process name(s) in kernel"),
            (pids, names) => {
                format!("Capturing {pids} PID(s) + {names} process name(s) in kernel")
            }
        };
        self.send_config();
    }

    fn prune_history_to_capture(&mut self) {
        if self.active_capture_pids.is_empty() && self.active_capture_names.is_empty() {
            return;
        }
        self.events.clear();
        self.visible.clear();
        self.details.clear();
        self.outcomes.clear();
        self.category_counts = [0; 10];
        self.history_evicted = 0;
        self.selected = None;
        self.filters_dirty = true;
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let capture_label = if self.capture {
                "⏸ Pause"
            } else {
                "▶ Capture"
            };
            if ui.button(capture_label).clicked() {
                self.capture = !self.capture;
                self.send_config();
            }
            if ui.button("Clear").clicked() {
                self.events.clear();
                self.visible.clear();
                self.details.clear();
                self.outcomes.clear();
                self.category_counts = [0; 10];
                self.history_evicted = 0;
                self.selected = None;
            }
            ui.separator();
            ui.selectable_value(&mut self.view, View::Events, "Events");
            ui.selectable_value(&mut self.view, View::Processes, "Processes");
            ui.selectable_value(&mut self.view, View::Statistics, "Statistics");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.checkbox(&mut self.dark_mode, "Dark").changed() {
                    apply_theme(ui.ctx(), self.dark_mode);
                }
                let apply = ui.button("Apply").clicked();
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.capture_process_text)
                        .hint_text("process1, process2")
                        .desired_width(190.0),
                );
                ui.label("Capture process")
                    .on_hover_text(
                        "Process making the syscall, not the syscall target. Names are matched in the kernel immediately.",
                    );
                if apply
                    || (response.lost_focus()
                        && ui.input(|input| input.key_pressed(egui::Key::Enter)))
                {
                    self.apply_capture_process();
                }
            });
        });
    }

    fn add_operation_rule(&mut self, include: bool) -> bool {
        let wanted = self.operation_filter_input.trim();
        if wanted.is_empty() {
            self.operation_filter_status = "Enter an operation name".into();
            return false;
        }
        let Some(name) = self
            .syscall_names
            .iter()
            .find(|name| !name.is_empty() && name.eq_ignore_ascii_case(wanted))
            .cloned()
        else {
            self.operation_filter_status = format!("Unknown operation: {wanted}");
            return false;
        };

        if include {
            self.excluded_operations.remove(&name);
            self.included_operations.insert(name.clone());
        } else {
            self.included_operations.remove(&name);
            self.excluded_operations.insert(name.clone());
        }
        self.operation_filter_input.clear();
        self.operation_filter_status =
            format!("{} {name}", if include { "Included" } else { "Excluded" });
        true
    }

    fn filter_bar(&mut self, ui: &mut egui::Ui) {
        let mut changed = false;
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Operations").strong());
            for (index, name) in CATEGORIES.iter().enumerate() {
                let mut enabled = self.category_mask & (1 << index) != 0;
                if ui.toggle_value(&mut enabled, *name).changed() {
                    if enabled {
                        self.category_mask |= 1 << index;
                    } else {
                        self.category_mask &= !(1 << index);
                    }
                    changed = true;
                }
            }
            let filter_count = self.included_operations.len() + self.excluded_operations.len();
            let menu_label = if filter_count == 0 {
                "...".to_owned()
            } else {
                format!("... {filter_count}")
            };
            egui::containers::menu::MenuButton::new(menu_label)
                .config(
                    egui::containers::menu::MenuConfig::new()
                        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside),
                )
                .ui(ui, |ui| {
                    ui.set_min_width(390.0);
                    ui.strong("Operation filters");
                    ui.horizontal(|ui| {
                        let response = ui.add(
                            egui::TextEdit::singleline(&mut self.operation_filter_input)
                                .hint_text("NtOpenProcess")
                                .desired_width(210.0),
                        );
                        if response.changed() {
                            self.operation_filter_status.clear();
                        }
                        if ui.button("Include").clicked() && self.add_operation_rule(true) {
                            changed = true;
                        }
                        if ui.button("Exclude").clicked() && self.add_operation_rule(false) {
                            changed = true;
                        }
                    });
                    if !self.operation_filter_status.is_empty() {
                        ui.weak(&self.operation_filter_status);
                    }
                    ui.separator();
                    let mut rules: Vec<(bool, String)> = self
                        .included_operations
                        .iter()
                        .cloned()
                        .map(|name| (true, name))
                        .chain(
                            self.excluded_operations
                                .iter()
                                .cloned()
                                .map(|name| (false, name)),
                        )
                        .collect();
                    rules.sort_unstable_by(|left, right| left.1.cmp(&right.1));
                    if rules.is_empty() {
                        ui.weak("No operation filters");
                    }
                    egui::ScrollArea::vertical()
                        .max_height(240.0)
                        .show(ui, |ui| {
                            for (included, name) in &rules {
                                ui.horizontal(|ui| {
                                    ui.add_sized(
                                        [80.0, 18.0],
                                        egui::Label::new(if *included {
                                            "Include"
                                        } else {
                                            "Exclude"
                                        }),
                                    );
                                    ui.add_sized(
                                        [210.0, 18.0],
                                        egui::Label::new(RichText::new(name).monospace())
                                            .truncate(),
                                    );
                                    if ui.small_button("Remove").clicked() {
                                        self.included_operations.remove(name);
                                        self.excluded_operations.remove(name);
                                        changed = true;
                                    }
                                });
                            }
                        });
                    if !rules.is_empty() && ui.button("Clear all").clicked() {
                        self.included_operations.clear();
                        self.excluded_operations.clear();
                        changed = true;
                    }
                });
        });
        ui.horizontal(|ui| {
            ui.label("Process");
            if ui
                .add(
                    egui::TextEdit::singleline(&mut self.process_filter)
                        .hint_text("name.exe")
                        .desired_width(130.0),
                )
                .changed()
            {
                changed = true;
            }
            ui.label("Search");
            if ui
                .add(
                    egui::TextEdit::singleline(&mut self.search)
                        .hint_text("operation, PID or arguments"),
                )
                .changed()
            {
                changed = true;
            }
            ui.label("TID");
            if ui
                .add(egui::TextEdit::singleline(&mut self.tid_filter).desired_width(80.0))
                .changed()
            {
                changed = true;
            }
            if ui.button("Reset filters").clicked() {
                self.search.clear();
                self.process_filter.clear();
                self.tid_filter.clear();
                self.category_mask = ALL_CATEGORIES;
                self.included_operations.clear();
                self.excluded_operations = HashSet::from([DEFAULT_EXCLUDED_OPERATION.to_owned()]);
                changed = true;
            }
        });
        if changed {
            self.filters_dirty = true;
            self.send_config();
        }
    }

    fn events_view(&mut self, ui: &mut egui::Ui) {
        self.filter_bar(ui);
        ui.separator();
        let names = &self.syscall_names;
        let events = &self.events;
        let visible = &self.visible;
        let details = &self.details;
        let outcomes = &self.outcomes;
        let processes = &self.processes;
        let default_process_icon = &self.default_process_icon;
        let included_operations = &self.included_operations;
        let excluded_operations = &self.excluded_operations;
        let dark_mode = self.dark_mode;
        let selected = &mut self.selected;
        let mut operation_action = None;
        let table = TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .column(Column::exact(68.0))
            .column(Column::exact(72.0))
            .column(Column::initial(170.0).at_least(110.0))
            .column(Column::exact(72.0))
            .column(Column::initial(210.0).at_least(130.0))
            .column(Column::initial(100.0))
            .column(Column::remainder().at_least(180.0))
            .stick_to_bottom(true);
        table
            .header(22.0, |mut header| {
                for title in [
                    "Time",
                    "PID",
                    "Process",
                    "TID",
                    "Operation",
                    "Class",
                    "Arguments",
                ] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(21.0, visible.len(), |mut row| {
                    let event_index = visible[row.index()];
                    let event = events[event_index];
                    let operation = export::name_for(names, event.syscall_id);
                    row.set_selected(*selected == Some(event_index));
                    row.col(|ui| {
                        ui.monospace(format_event_time(event.qpc));
                    });
                    row.col(|ui| {
                        ui.monospace(event.pid.to_string());
                    });
                    row.col(|ui| {
                        let process = processes.iter().find(|process| process.pid == event.pid);
                        ui.horizontal(|ui| {
                            if let Some(icon) = process.and_then(|process| process.icon.as_ref()) {
                                ui.image((icon.id(), egui::vec2(16.0, 16.0)));
                            } else {
                                ui.image((default_process_icon.id(), egui::vec2(16.0, 16.0)));
                            }
                            ui.label(
                                process
                                    .map(|process| process.name.as_str())
                                    .or_else(|| event.process_name())
                                    .unwrap_or("Unknown"),
                            );
                        });
                    });
                    row.col(|ui| {
                        ui.monospace(event.tid.to_string());
                    });
                    let (_, operation_response) = row.col(|ui| {
                        ui.add(egui::Label::new(RichText::new(operation).monospace()).truncate());
                    });
                    operation_response.context_menu(|ui| {
                        event_context_menu(
                            ui,
                            event,
                            &mut EventMenuContext {
                                names,
                                details,
                                outcomes,
                                processes,
                                included_operations,
                                excluded_operations,
                                operation_action: &mut operation_action,
                            },
                        );
                    });
                    row.col(|ui| {
                        let name = CATEGORIES
                            .get(event.category as usize)
                            .copied()
                            .unwrap_or("Other");
                        ui.colored_label(category_color(event.category, dark_mode), name);
                    });
                    row.col(|ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(argument_text(details, &event, operation).as_ref())
                                    .monospace(),
                            )
                            .truncate(),
                        );
                    });
                    if row.response().clicked() {
                        *selected = Some(event_index);
                    }
                });
            });
        if let Some(action) = operation_action {
            self.apply_operation_filter(action);
        }
    }

    fn processes_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Refresh").clicked() {
                self.refresh_processes(ui.ctx());
            }
            ui.label("Double-click a process to capture only calls made by it.");
        });
        ui.separator();
        let mut chosen = None;
        TableBuilder::new(ui)
            .striped(true)
            .sense(egui::Sense::click())
            .resizable(true)
            .column(Column::initial(180.0))
            .column(Column::exact(80.0))
            .column(Column::exact(80.0))
            .column(Column::remainder())
            .header(22.0, |mut header| {
                for title in ["Process", "PID", "Parent", "Path"] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(21.0, self.processes.len(), |mut row| {
                    let process = &self.processes[row.index()];
                    row.col(|ui| {
                        ui.horizontal(|ui| {
                            if let Some(icon) = &process.icon {
                                ui.image((icon.id(), egui::vec2(16.0, 16.0)));
                            } else {
                                ui.image((self.default_process_icon.id(), egui::vec2(16.0, 16.0)));
                            }
                            ui.label(&process.name);
                        });
                    });
                    row.col(|ui| {
                        ui.monospace(process.pid.to_string());
                    });
                    row.col(|ui| {
                        ui.monospace(process.parent.to_string());
                    });
                    row.col(|ui| {
                        ui.label(&process.path);
                    });
                    if row.response().double_clicked() {
                        chosen = Some(process.pid);
                    }
                });
            });
        if let Some(pid) = chosen {
            self.capture_process_text = self
                .processes
                .iter()
                .find(|process| process.pid == pid)
                .map_or_else(String::new, |process| process.name.clone());
            self.apply_capture_process();
            self.view = View::Events;
        }
    }

    fn statistics_view(&mut self, ui: &mut egui::Ui) {
        let fill = if self.dark_mode {
            Color32::from_rgb(38, 41, 46)
        } else {
            Color32::from_rgb(218, 220, 224)
        };
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.heading("Capture statistics");
                egui::Frame::group(ui.style()).fill(fill).show(ui, |ui| {
                    egui::Grid::new("stats-grid")
                        .spacing([28.0, 7.0])
                        .show(ui, |ui| {
                            stat_row(ui, "Captured by driver", self.stats.captured);
                            stat_row(ui, "Delivered to collector", self.stats.delivered);
                            stat_row(ui, "Dropped in kernel ring", self.stats.dropped);
                            stat_row(ui, "Dropped syscall details", self.stats.details_dropped);
                            stat_row(ui, "Evicted by history limit", self.history_evicted);
                            stat_row(ui, "Retained in memory", self.events.len() as u64);
                            stat_row(ui, "Currently visible", self.visible.len() as u64);
                            stat_row(ui, "Kernel queue", self.stats.ring_queued as u64);
                        });
                });
            });
            ui.add_space(18.0);
            ui.vertical(|ui| {
                ui.heading("Operations by class");
                egui::Frame::group(ui.style()).fill(fill).show(ui, |ui| {
                    egui::Grid::new("class-counts")
                        .spacing([28.0, 7.0])
                        .show(ui, |ui| {
                            for (index, name) in CATEGORIES.iter().enumerate() {
                                ui.colored_label(
                                    category_color(index as u16, self.dark_mode),
                                    *name,
                                );
                                ui.monospace(compact_number(self.category_counts[index]));
                                ui.end_row();
                            }
                        });
                });
            });
        });
    }

    fn bottom_panel(&mut self, root: &mut egui::Ui) {
        egui::Panel::bottom("bottom").show(root, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!(
                    "{} | retained {} / {} | visible {}",
                    self.status,
                    self.events.len(),
                    self.max_events,
                    self.visible.len()
                ));
                if self.stats.dropped > 0 {
                    ui.colored_label(
                        Color32::LIGHT_RED,
                        format!("lost kernel={}", self.stats.dropped),
                    );
                }
            });
            ui.horizontal(|ui| {
                ui.label("Memory limit");
                let limit_response = ui.add(
                    egui::Slider::new(&mut self.max_events, 10_000..=1_000_000).logarithmic(true),
                );
                if limit_response.changed() {
                    if self.events.len() > self.max_events {
                        let remove = self.events.len() - self.max_events;
                        self.events.drain(..remove);
                        self.history_evicted += remove as u64;
                        self.selected = None;
                    }
                    if self.events.capacity() > self.max_events.saturating_mul(2) {
                        self.events.shrink_to(self.max_events);
                        self.visible.shrink_to(self.max_events);
                        self.details.shrink_to(self.max_events);
                        self.outcomes.shrink_to(self.max_events);
                    }
                    self.filters_dirty = true;
                }
                ui.weak(format!(
                    "≈ {} MiB",
                    self.max_events.saturating_mul(ESTIMATED_BYTES_PER_EVENT) / (1024 * 1024)
                ));
                ui.separator();
                ui.label("Export");
                ui.add(egui::TextEdit::singleline(&mut self.export_path).desired_width(240.0));
                if ui.button("CSV").clicked() {
                    self.do_export(ExportFormat::Csv);
                }
                if ui.button("JSONL").clicked() {
                    self.do_export(ExportFormat::Jsonl);
                }
                if ui.button("TXT").clicked() {
                    self.do_export(ExportFormat::Txt);
                }
                if !self.export_status.is_empty() {
                    ui.label(&self.export_status);
                }
            });
            if let Some(index) = self
                .selected
                .and_then(|index| self.events.get(index).map(|_| index))
            {
                let event = self.events[index];
                let operation = export::name_for(&self.syscall_names, event.syscall_id);
                ui.separator();
                ui.monospace(format!(
                    "Selected: seq={} PID={} TID={} syscall=0x{:04X} {} ({}) Arguments={} Result={}",
                    event.sequence,
                    event.pid,
                    event.tid,
                    event.syscall_id,
                    operation,
                    CATEGORIES
                        .get(event.category as usize)
                        .copied()
                        .unwrap_or("Other"),
                    argument_text(&self.details, &event, operation),
                    self.outcomes
                        .get(&event.sequence)
                        .map_or(UNKNOWN_RESULT, String::as_str)
                ));
            }
        });
    }

    fn do_export(&mut self, format: ExportFormat) {
        let base = self.export_path.trim();
        let mut path = PathBuf::from(if base.is_empty() { "syscalls" } else { base });
        path.set_extension(format.extension());
        let process_names: HashMap<u32, String> = self
            .processes
            .iter()
            .map(|process| (process.pid, process.name.clone()))
            .collect();
        let result = match format {
            ExportFormat::Csv => export::export_csv(
                &path,
                &self.events,
                &self.visible,
                &self.syscall_names,
                &self.details,
                &self.outcomes,
                &process_names,
            ),
            ExportFormat::Jsonl => export::export_jsonl(
                &path,
                &self.events,
                &self.visible,
                &self.syscall_names,
                &self.details,
                &self.outcomes,
                &process_names,
            ),
            ExportFormat::Txt => export::export_txt(
                &path,
                &self.events,
                &self.visible,
                &self.syscall_names,
                &self.details,
                &self.outcomes,
                &process_names,
            ),
        };
        self.export_status = match result {
            Ok(()) => format!("saved {} rows to {}", self.visible.len(), path.display()),
            Err(error) => format!("export failed: {error}"),
        };
    }
}

impl eframe::App for MonitorApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_source();
        if self.last_process_refresh.elapsed() >= Duration::from_secs(5) {
            self.refresh_processes(ui.ctx());
        }
        if ui.style().visuals.dark_mode != self.dark_mode {
            apply_theme(ui.ctx(), self.dark_mode);
        }
        self.bottom_panel(ui);
        egui::Panel::top("top").show(ui, |ui| self.top_bar(ui));
        egui::CentralPanel::default().show(ui, |ui| match self.view {
            View::Events => self.events_view(ui),
            View::Processes => self.processes_view(ui),
            View::Statistics => self.statistics_view(ui),
        });
        ui.ctx().request_repaint_after(Duration::from_millis(33));
    }
}

impl Drop for MonitorApp {
    fn drop(&mut self) {
        let _ = self.source.commands.send(SourceCommand::Stop);
    }
}

fn category_color(category: u16, dark_mode: bool) -> Color32 {
    let dark = [
        Color32::from_rgb(102, 178, 255),
        Color32::from_rgb(255, 184, 108),
        Color32::from_rgb(80, 250, 123),
        Color32::from_rgb(139, 233, 253),
        Color32::from_rgb(189, 147, 249),
        Color32::from_rgb(255, 121, 198),
        Color32::from_rgb(241, 250, 140),
        Color32::from_rgb(255, 160, 122),
        Color32::from_rgb(144, 238, 144),
        Color32::from_rgb(195, 199, 207),
    ];
    let light = [
        Color32::from_rgb(0, 84, 166),
        Color32::from_rgb(150, 76, 0),
        Color32::from_rgb(0, 112, 52),
        Color32::from_rgb(0, 105, 120),
        Color32::from_rgb(91, 45, 145),
        Color32::from_rgb(157, 28, 102),
        Color32::from_rgb(132, 98, 0),
        Color32::from_rgb(163, 56, 25),
        Color32::from_rgb(24, 110, 54),
        Color32::from_rgb(65, 68, 74),
    ];
    (if dark_mode { dark } else { light })
        .get(category as usize)
        .copied()
        .unwrap_or(Color32::LIGHT_GRAY)
}

fn stat_row(ui: &mut egui::Ui, name: &str, value: u64) {
    ui.label(name);
    ui.monospace(value.to_string());
    ui.end_row();
}

fn parse_capture_filters(value: &str) -> (Vec<u32>, Vec<String>) {
    let value = value.trim();
    if value.is_empty() || value == "*" || value == "0" {
        return (Vec::new(), Vec::new());
    }

    let mut pids = Vec::new();
    let mut names = Vec::new();
    for token in value
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        if pids.len() + names.len() >= MAX_TARGET_PIDS {
            break;
        }
        if token == "*" {
            return (Vec::new(), Vec::new());
        }
        if let Ok(pid) = token.parse::<u32>() {
            if pid != 0 && !pids.contains(&pid) {
                pids.push(pid);
            }
            continue;
        }

        let basename = token
            .trim_matches('"')
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(token)
            .trim();
        let lowercase = basename.to_ascii_lowercase();
        let normalized = lowercase.strip_suffix(".exe").unwrap_or(&lowercase);
        if !normalized.is_empty() && !names.iter().any(|name| name == normalized) {
            names.push(normalized.to_owned());
        }
    }
    (pids, names)
}

fn encode_kernel_process_name(name: &str) -> [u8; PROCESS_NAME_BYTES] {
    let mut output = [0_u8; PROCESS_NAME_BYTES];
    for (slot, byte) in output
        .iter_mut()
        .take(PROCESS_NAME_BYTES - 1)
        .zip(name.bytes())
    {
        *slot = byte.to_ascii_lowercase();
    }
    output
}

fn recommended_event_limit(available_memory: u64) -> usize {
    let budget = (available_memory / 100).clamp(2 * 1024 * 1024, 128 * 1024 * 1024);
    usize::try_from(budget)
        .unwrap_or(128 * 1024 * 1024)
        .saturating_div(ESTIMATED_BYTES_PER_EVENT)
        .clamp(10_000, 1_000_000)
}

fn compact_number(value: u64) -> String {
    if value < 1_000 {
        return value.to_string();
    }
    for (threshold, suffix) in [(1_000_000_000_u64, "B"), (1_000_000, "M"), (1_000, "K")] {
        if value >= threshold {
            let scaled = value as f64 / threshold as f64;
            return if scaled < 10.0 {
                format!("{scaled:.1}{suffix}")
            } else {
                format!("{scaled:.0}{suffix}")
            };
        }
    }
    value.to_string()
}

fn format_event_time(seconds: u64) -> String {
    let seconds = seconds % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3_600,
        seconds / 60 % 60,
        seconds % 60
    )
}

fn trim_auxiliary_map(values: &mut HashMap<u64, String>, limit: usize) {
    if values.len() <= limit {
        return;
    }
    let remove = values.len() - limit;
    let mut sequences: Vec<_> = values.keys().copied().collect();
    sequences.select_nth_unstable(remove - 1);
    for sequence in sequences.into_iter().take(remove) {
        values.remove(&sequence);
    }
}

fn argument_text<'a>(
    details: &'a HashMap<u64, String>,
    event: &RawEvent,
    operation: &str,
) -> Cow<'a, str> {
    details.get(&event.sequence).map_or_else(
        || Cow::Owned(event.display_arguments(operation)),
        |value| Cow::Borrowed(value.as_str()),
    )
}

fn event_process_name<'a>(event: &'a RawEvent, processes: &'a [ProcessRow]) -> &'a str {
    processes
        .iter()
        .find(|process| process.pid == event.pid)
        .map(|process| process.name.as_str())
        .or_else(|| event.process_name())
        .unwrap_or("Unknown")
}

fn load_default_process_icon(ctx: &egui::Context) -> egui::TextureHandle {
    let image = process_icon::load_default().unwrap_or_else(|| {
        let icon =
            eframe::icon_data::from_png_bytes(include_bytes!("../resources/window-icon.png"))
                .expect("embedded application icon must be a valid PNG");
        egui::ColorImage::from_rgba_unmultiplied(
            [icon.width as usize, icon.height as usize],
            &icon.rgba,
        )
    });
    ctx.load_texture("default-process-icon", image, egui::TextureOptions::LINEAR)
}

fn apply_theme(ctx: &egui::Context, dark_mode: bool) {
    let mut visuals = if dark_mode {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    if dark_mode {
        visuals.panel_fill = Color32::from_rgb(29, 31, 35);
        visuals.window_fill = Color32::from_rgb(35, 38, 43);
        visuals.extreme_bg_color = Color32::from_rgb(22, 24, 28);
    } else {
        visuals.panel_fill = Color32::from_rgb(226, 228, 232);
        visuals.window_fill = Color32::from_rgb(235, 236, 239);
        visuals.extreme_bg_color = Color32::from_rgb(211, 214, 219);
    }
    ctx.set_visuals(visuals);
}

fn event_context_menu(ui: &mut egui::Ui, event: RawEvent, context: &mut EventMenuContext<'_>) {
    let operation = export::name_for(context.names, event.syscall_id);
    let process = event_process_name(&event, context.processes);
    let category = CATEGORIES
        .get(event.category as usize)
        .copied()
        .unwrap_or("Other");
    let arguments = argument_text(context.details, &event, operation);

    ui.strong(operation);
    ui.monospace(format!("Syscall ID: 0x{:04X}", event.syscall_id));
    ui.label(format!("Process: {process} ({})", event.pid));
    ui.label(format!("Thread: {}", event.tid));
    ui.label(format!("Time: {}", format_event_time(event.qpc)));
    ui.label(format!("Class: {category}"));
    ui.label(format!("Sequence: {}", event.sequence));
    ui.separator();
    ui.label("Arguments");
    ui.add(
        egui::Label::new(if arguments.is_empty() {
            "—"
        } else {
            arguments.as_ref()
        })
        .wrap(),
    );
    ui.label("Result");
    ui.monospace(
        context
            .outcomes
            .get(&event.sequence)
            .map_or(UNKNOWN_RESULT, String::as_str),
    );
    ui.separator();
    if ui.button(format!("Include {operation}")).clicked() {
        *context.operation_action = Some(OperationFilterAction::Include(operation.to_owned()));
        ui.close();
    }
    if ui.button(format!("Exclude {operation}")).clicked() {
        *context.operation_action = Some(OperationFilterAction::Exclude(operation.to_owned()));
        ui.close();
    }
    if (context.included_operations.contains(operation)
        || context.excluded_operations.contains(operation))
        && ui.button("Clear operation rule").clicked()
    {
        *context.operation_action = Some(OperationFilterAction::Clear(operation.to_owned()));
        ui.close();
    }
    ui.separator();
    if ui.button("Copy operation").clicked() {
        ui.ctx().copy_text(operation.to_owned());
        ui.close();
    }
    if !arguments.is_empty() && ui.button("Copy arguments").clicked() {
        ui.ctx().copy_text(arguments.to_string());
        ui.close();
    }
    if ui.button("Copy full event").clicked() {
        let result = context
            .outcomes
            .get(&event.sequence)
            .map_or(UNKNOWN_RESULT, String::as_str);
        ui.ctx().copy_text(format!(
            "#{seq} {process} PID={pid} TID={tid} {operation} [{category}] {arguments} => {result}",
            seq = event.sequence,
            pid = event.pid,
            tid = event.tid,
        ));
        ui.close();
    }
}

fn main() -> eframe::Result {
    install_panic_log();
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../resources/window-icon.png"))
        .expect("embedded application icon must be a valid PNG");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Syscall Monitor")
            .with_inner_size([1180.0, 760.0])
            .with_icon(icon),
        ..Default::default()
    };
    eframe::run_native(
        "Syscall Monitor",
        options,
        Box::new(|cc| Ok(Box::new(MonitorApp::new(cc)))),
    )
}

fn install_panic_log() {
    std::panic::set_hook(Box::new(|info| {
        let path = std::env::current_exe()
            .ok()
            .and_then(|path| {
                path.parent()
                    .map(|parent| parent.join("scall-monitor-crash.log"))
            })
            .unwrap_or_else(|| "scall-monitor-crash.log".into());
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{info}");
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::{encode_kernel_process_name, parse_capture_filters};
    use crate::protocol::{EVENT_FLAG_ARGUMENTS_VALID, RawEvent};

    #[test]
    fn capture_filters_keep_names_for_kernel_matching() {
        let (pids, names) =
            parse_capture_filters(r#"jvm_ex.exe, C:\tools\Worker.EXE, 6616, jvm_ex, 6616"#);
        assert_eq!(pids, [6616]);
        assert_eq!(names, ["jvm_ex", "worker"]);
    }

    #[test]
    fn wildcard_means_capture_every_process() {
        let (pids, names) = parse_capture_filters("jvm_ex.exe, *");
        assert!(pids.is_empty());
        assert!(names.is_empty());
    }

    #[test]
    fn kernel_name_is_lowercase_and_bounded() {
        let encoded = encode_kernel_process_name("VeryLongProcessName");
        assert_eq!(&encoded[..15], b"verylongprocess");
        assert_eq!(encoded[15], 0);
    }

    #[test]
    fn unavailable_arguments_are_not_reported_as_zeroes() {
        let mut event = RawEvent::default();
        assert_eq!(event.display_arguments("NtUnknown"), "unavailable");
        event.flags = EVENT_FLAG_ARGUMENTS_VALID;
        assert_eq!(event.display_arguments("NtUnknown"), "0x0, 0x0, 0x0, 0x0");
    }
}
