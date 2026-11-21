use core::mem::MaybeUninit;

#[link(wasm_import_module = "env")]
unsafe extern "C" {
    fn h_storage_read(key: *const u8, key_len: usize, value: *mut u8) -> i32;
}

const MAX_VALUE_BYTES: usize = 65_536;

/// ABI v1 returns the size after copying. Reserve room for the host's largest
/// value even when the caller expects a much smaller, fixed-width record.
pub fn read_into(key: &[u8], out: &mut [u8]) -> Result<usize, ()> {
    let mut scratch = MaybeUninit::<[u8; MAX_VALUE_BYTES]>::uninit();
    let ptr = scratch.as_mut_ptr().cast::<u8>();
    // SAFETY: the VM caps each value at 65,536 bytes. A successful read
    // initializes precisely the returned prefix. Missing keys return zero.
    let copied = unsafe { h_storage_read(key.as_ptr(), key.len(), ptr) };
    let len = usize::try_from(copied).map_err(|_| ())?;
    if len > out.len() || len > MAX_VALUE_BYTES {
        return Err(());
    }
    // SAFETY: both ranges cover len bytes, are disjoint and the source prefix
    // was initialized by the host. An oversized value never reaches `out`.
    unsafe { core::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), len) };
    Ok(len)
}
