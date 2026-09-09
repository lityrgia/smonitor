use eframe::egui::ColorImage;

#[cfg(not(windows))]
pub fn load(_path: &str) -> Option<ColorImage> {
    None
}

#[cfg(not(windows))]
pub fn load_default() -> Option<ColorImage> {
    None
}

#[cfg(windows)]
pub fn load(path: &str) -> Option<ColorImage> {
    load_shell_icon(path, 0, false)
}

#[cfg(windows)]
pub fn load_default() -> Option<ColorImage> {
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;

    load_shell_icon(".exe", FILE_ATTRIBUTE_NORMAL, true)
}

#[cfg(windows)]
fn load_shell_icon(path: &str, attributes: u32, use_file_attributes: bool) -> Option<ColorImage> {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::ptr::null_mut;
    use windows_sys::Win32::Graphics::Gdi::{
        BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, CreateDIBSection, DIB_RGB_COLORS,
        DeleteDC, DeleteObject, SelectObject,
    };
    use windows_sys::Win32::UI::Shell::{
        SHFILEINFOW, SHGFI_ICON, SHGFI_SMALLICON, SHGFI_USEFILEATTRIBUTES, SHGetFileInfoW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{DI_NORMAL, DestroyIcon, DrawIconEx};

    if path.is_empty() {
        return None;
    }
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut file_info: SHFILEINFOW = unsafe { zeroed() };
    let flags = SHGFI_ICON
        | SHGFI_SMALLICON
        | if use_file_attributes {
            SHGFI_USEFILEATTRIBUTES
        } else {
            0
        };
    let result = unsafe {
        SHGetFileInfoW(
            wide.as_ptr(),
            attributes,
            &mut file_info,
            size_of::<SHFILEINFOW>() as u32,
            flags,
        )
    };
    if result == 0 || file_info.hIcon.is_null() {
        return None;
    }

    const SIZE: usize = 20;
    let dc = unsafe { CreateCompatibleDC(null_mut()) };
    if dc.is_null() {
        unsafe { DestroyIcon(file_info.hIcon) };
        return None;
    }
    let mut bitmap_info = BITMAPINFO::default();
    bitmap_info.bmiHeader = BITMAPINFOHEADER {
        biSize: size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: SIZE as i32,
        biHeight: -(SIZE as i32),
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB,
        ..Default::default()
    };
    let mut bits: *mut c_void = null_mut();
    let bitmap =
        unsafe { CreateDIBSection(dc, &bitmap_info, DIB_RGB_COLORS, &mut bits, null_mut(), 0) };
    if bitmap.is_null() || bits.is_null() {
        unsafe {
            DeleteDC(dc);
            DestroyIcon(file_info.hIcon);
        }
        return None;
    }
    let previous = unsafe { SelectObject(dc, bitmap) };
    let drawn = unsafe {
        DrawIconEx(
            dc,
            0,
            0,
            file_info.hIcon,
            SIZE as i32,
            SIZE as i32,
            0,
            null_mut(),
            DI_NORMAL,
        )
    };
    let bgra = unsafe { std::slice::from_raw_parts(bits.cast::<u8>(), SIZE * SIZE * 4) };
    let mut rgba = vec![0_u8; bgra.len()];
    for (source, destination) in bgra.chunks_exact(4).zip(rgba.chunks_exact_mut(4)) {
        destination.copy_from_slice(&[source[2], source[1], source[0], source[3]]);
    }
    unsafe {
        SelectObject(dc, previous);
        DeleteObject(bitmap);
        DeleteDC(dc);
        DestroyIcon(file_info.hIcon);
    }
    (drawn != 0).then(|| ColorImage::from_rgba_unmultiplied([SIZE, SIZE], &rgba))
}
