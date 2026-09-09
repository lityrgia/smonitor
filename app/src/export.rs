use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::protocol::{CATEGORIES, RawEvent, UNKNOWN_RESULT};

pub fn export_csv(
    path: &Path,
    events: &[RawEvent],
    visible: &[usize],
    names: &[String],
    details: &HashMap<u64, String>,
    outcomes: &HashMap<u64, String>,
    process_names: &HashMap<u32, String>,
) -> std::io::Result<()> {
    let mut out = BufWriter::new(File::create(path)?);
    writeln!(
        out,
        "pid,process,tid,syscall_id,category,operation,arguments,result"
    )?;
    for &index in visible {
        let row = export_row(events[index], names, details, outcomes, process_names);
        writeln!(
            out,
            "{},\"{}\",{},0x{:04X},{},\"{}\",\"{}\",\"{}\"",
            row.event.pid,
            csv_escape(&row.process),
            row.event.tid,
            row.event.syscall_id,
            category_name(row.event.category),
            csv_escape(row.operation),
            csv_escape(&row.arguments),
            csv_escape(row.result),
        )?;
    }
    Ok(())
}

pub fn export_jsonl(
    path: &Path,
    events: &[RawEvent],
    visible: &[usize],
    names: &[String],
    details: &HashMap<u64, String>,
    outcomes: &HashMap<u64, String>,
    process_names: &HashMap<u32, String>,
) -> std::io::Result<()> {
    let mut out = BufWriter::new(File::create(path)?);
    for &index in visible {
        let row = export_row(events[index], names, details, outcomes, process_names);
        writeln!(
            out,
            "{{\"pid\":{},\"process\":\"{}\",\"tid\":{},\"syscall_id\":{},\"category\":\"{}\",\"operation\":\"{}\",\"arguments\":\"{}\",\"result\":\"{}\"}}",
            row.event.pid,
            json_escape(&row.process),
            row.event.tid,
            row.event.syscall_id,
            json_escape(category_name(row.event.category)),
            json_escape(row.operation),
            json_escape(&row.arguments),
            json_escape(row.result),
        )?;
    }
    Ok(())
}

pub fn export_txt(
    path: &Path,
    events: &[RawEvent],
    visible: &[usize],
    names: &[String],
    details: &HashMap<u64, String>,
    outcomes: &HashMap<u64, String>,
    process_names: &HashMap<u32, String>,
) -> std::io::Result<()> {
    let mut out = BufWriter::new(File::create(path)?);
    for &index in visible {
        let row = export_row(events[index], names, details, outcomes, process_names);
        writeln!(
            out,
            "{} ({}) TID={} {} [{}] {} => {}",
            row.process,
            row.event.pid,
            row.event.tid,
            row.operation,
            category_name(row.event.category),
            row.arguments,
            row.result,
        )?;
    }
    Ok(())
}

pub fn name_for(names: &[String], id: u16) -> &str {
    names
        .get(id as usize)
        .filter(|name| !name.is_empty())
        .map_or("Unknown", String::as_str)
}

fn category_name(category: u16) -> &'static str {
    CATEGORIES
        .get(category as usize)
        .copied()
        .unwrap_or("Other")
}

fn process_name<'a>(process_names: &'a HashMap<u32, String>, event: &'a RawEvent) -> &'a str {
    process_names
        .get(&event.pid)
        .map(String::as_str)
        .or_else(|| event.process_name())
        .unwrap_or("Unknown")
}

struct ExportRow<'a> {
    event: RawEvent,
    process: String,
    operation: &'a str,
    arguments: String,
    result: &'a str,
}

fn export_row<'a>(
    event: RawEvent,
    names: &'a [String],
    details: &'a HashMap<u64, String>,
    outcomes: &'a HashMap<u64, String>,
    process_names: &'a HashMap<u32, String>,
) -> ExportRow<'a> {
    let operation = name_for(names, event.syscall_id);
    let process = process_name(process_names, &event).to_owned();
    let arguments = details
        .get(&event.sequence)
        .cloned()
        .unwrap_or_else(|| event.display_arguments(operation));
    let result = outcomes
        .get(&event.sequence)
        .map_or(UNKNOWN_RESULT, String::as_str);
    ExportRow {
        event,
        process,
        operation,
        arguments,
        result,
    }
}

fn csv_escape(value: &str) -> String {
    value.replace('"', "\"\"")
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
