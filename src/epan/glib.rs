
#[derive(Debug)]
#[repr(C)]
pub struct GPtrArray {
  pdata: *mut *mut libc::c_void,
  len: u32,
}
impl GPtrArray
{
    pub fn len(self: &Self) -> usize
    {
        return self.len as usize;
    }
    pub unsafe fn index(self: &Self, index: isize) -> *mut libc::c_void
    {
        // This is actually a macro in the code.
        return *(self.pdata).offset(index);
    }
}

#[link(name = "glib-2.0")]
extern "C" {
    pub fn g_ptr_array_free(array: *mut GPtrArray, free_seg: bool);
}

