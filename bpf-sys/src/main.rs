use libbpf_sys::{bpf_object__open_file, bpf_object__find_program_by_name, libbpf_get_error, bpf_object__load, bpf_program__attach, bpf_link__destroy, bpf_object__close};
use std::io::Read;
use std::{os::raw::c_char, ffi::CString};
use std::ffi::c_void;

fn convert(s: &str) -> *const c_char {
    let cs = CString::new(s).unwrap();

    let ptr = cs.as_ptr();
    std::mem::forget(cs);

    ptr
}

fn read_trace_pipe() {
    let mut pipe = std::fs::File::open("/sys/kernel/debug/tracing/trace_pipe").unwrap();
    let mut buf = [0; 1024];
    loop {
        let n = pipe.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        let s = String::from_utf8_lossy(&buf[..n]);
        println!("{}", s);
    }
}

fn main() {
    let filename = "src/bpf/kprobe.bpf.o";

    let obj = unsafe {
        let ptr = convert(filename);
        let obj = bpf_object__open_file(ptr, std::ptr::null());
        drop(CString::from_raw(ptr as *mut c_char));
        if libbpf_get_error(obj as *const c_void) != 0 {
            panic!("failed to open object");
        }
        obj
    };

    let prog = unsafe {
        let ptr = convert("bpf_prog1");
        let prog: *mut libbpf_sys::bpf_program = bpf_object__find_program_by_name(obj, ptr);
        drop(CString::from_raw(ptr as *mut c_char));
        if prog.is_null() {
            panic!("program not found");
        }

        prog
    };

    unsafe {
        if bpf_object__load(obj) != 0 {
            panic!("ERROR: loading BPF object file failed\n");
        }
    }

    let link = unsafe {
        let link = bpf_program__attach(prog);
        if libbpf_get_error(link as *const c_void) != 0 {
            panic!("ERROR: bpf_program__attach failed\n");
        }

        link
    };

    read_trace_pipe();

    unsafe  {
        bpf_link__destroy(link);
        bpf_object__close(obj);
    }
}
