#[cfg(not(test))]
extern "C" {
    fn check_app_canary();
    fn zemu_log_stack(ctx: *const u8);
    fn zemu_log(buf: *const u8);
}

pub fn z_check_app_canary() {
    #[cfg(not(test))]
    unsafe {
        check_app_canary()
    }
}

pub fn zlog(buf: &str) {
    #[cfg(not(test))]
    unsafe {
        zemu_log(buf.as_bytes().as_ptr())
    }
    #[cfg(test)]
    std::println!("{}", buf);
}
pub fn zlog_stack(buf: &str) {
    #[cfg(not(test))]
    unsafe {
        zemu_log_stack(buf.as_bytes().as_ptr())
    }
    #[cfg(test)]
    std::println!("{}", buf);
}
