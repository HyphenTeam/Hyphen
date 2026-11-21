pub type Account = [u8; 32];
mod storage;

#[link(wasm_import_module = "env")]
unsafe extern "C" {
    fn h_input_len() -> usize;
    fn h_input_copy(out: *mut u8) -> i32;
    fn h_caller(out: *mut u8) -> i32;
    fn h_storage_write(key: *const u8, len: usize, value: *const u8, size: usize) -> i32;
    fn h_set_return(value: *const u8, size: usize) -> i32;
}

pub fn request(buffer: &mut [u8]) -> &[u8] {
    let len = unsafe { h_input_len() };
    assert!(len <= buffer.len());
    assert_eq!(unsafe { h_input_copy(buffer.as_mut_ptr()) }, len as i32);
    &buffer[..len]
}

pub fn caller() -> Account {
    let mut account = [0; 32];
    assert_eq!(unsafe { h_caller(account.as_mut_ptr()) }, 0);
    account
}

pub fn read<const N: usize>(key: &[u8]) -> Option<[u8; N]> {
    let mut value = [0; N];
    let size = storage::read_into(key, &mut value).unwrap();
    if size == 0 {
        return None;
    }
    assert_eq!(size, N);
    Some(value)
}

pub fn write(key: &[u8], value: &[u8]) {
    assert_eq!(
        unsafe { h_storage_write(key.as_ptr(), key.len(), value.as_ptr(), value.len()) },
        0
    );
}

pub fn respond(value: &[u8]) {
    assert_eq!(unsafe { h_set_return(value.as_ptr(), value.len()) }, 0);
}
