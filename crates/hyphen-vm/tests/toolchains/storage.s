    .functype h_input_copy (i32) -> (i32)
    .functype h_storage_write (i32, i32, i32, i32) -> (i32)
    .functype h_storage_read (i32, i32, i32) -> (i32)
    .functype h_set_return (i32, i32) -> (i32)
    .text
    .globl hyphen_execute
hyphen_execute:
    .functype hyphen_execute () -> ()
    .local i32
    i32.const value
    call h_input_copy
    local.tee 0
    i32.const 0
    i32.lt_s
    if
    unreachable
    end_if
    i32.const key
    i32.const 3
    i32.const value
    local.get 0
    call h_storage_write
    if
    unreachable
    end_if
    end_function

    .globl hyphen_query
hyphen_query:
    .functype hyphen_query () -> ()
    .local i32
    i32.const key
    i32.const 3
    i32.const value
    call h_storage_read
    local.tee 0
    i32.const 0
    i32.lt_s
    if
    unreachable
    end_if
    i32.const value
    local.get 0
    call h_set_return
    if
    unreachable
    end_if
    end_function

    .section .rodata.key,"",@
key:
    .ascii "key"
    .size key, 3
    .section .bss.value,"",@
value:
    .skip 65536
    .size value, 65536
