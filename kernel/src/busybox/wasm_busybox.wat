;; WebAssembly Text Format for BusyBox commands
;; This provides a simple interface for busybox commands in WASM

(module
  ;; Import host functions for filesystem operations
  (import "host" "fs_read" (func $fs_read (param i32 i32 i32) (result i32)))
  (import "host" "fs_write" (func $fs_write (param i32 i32 i32) (result i32)))
  (import "host" "fs_open" (func $fs_open (param i32 i32) (result i32)))
  (import "host" "fs_close" (func $fs_close (param i32) (result i32)))
  (import "host" "fs_stat" (func $fs_stat (param i32 i32) (result i32)))
  (import "host" "fs_list" (func $fs_list (param i32 i32 i32) (result i32)))
  (import "host" "print" (func $print (param i32 i32)))
  (import "host" "get_time" (func $get_time (result i64)))
  (import "host" "get_memory_info" (func $get_memory_info (param i32)))

  ;; Memory for string operations
  (memory 1)
  (export "memory" (memory 0))

  ;; Data section with some strings
  (data (i32.const 0) "BusyBox v1.36.1 (WASM) multi-call binary\n")
  (data (i32.const 64) "Usage: ")
  (data (i32.const 128) "\n")
  (data (i32.const 256) "Error: ")
  (data (i32.const 512) "No such file or directory\n")
  (data (i32.const 1024) "Permission denied\n")
  (data (i32.const 2048) "/")
  
  ;; Buffer for file operations starts at 4096
  (global $buffer_start (mut i32) (i32.const 4096))
  
  ;; Echo command
  (func $echo (export "echo") (param $argc i32) (param $argv i32) (result i32)
    local.get $argc
    i32.const 1
    i32.gt_s
    if
      ;; Print arguments
      i32.const 1
      local.set $argc
      loop
        local.get $argv
        local.get $argc
        i32.const 4
        i32.mul
        i32.add
        i32.load
        
        ;; Get string length (simplified)
        i32.const 256
        call $print
        
        local.get $argc
        i32.const 1
        i32.add
        local.tee $argc
        local.get $argv
        i32.load
        i32.lt_s
        br_if 0
      end
    end
    
    ;; Print newline
    i32.const 128
    i32.const 1
    call $print
    i32.const 0
  )

  ;; Ls command
  (func $ls (export "ls") (param $argc i32) (param $argv i32) (result i32)
    (local $path i32)
    (local $buffer i32)
    (local $result i32)
    
    ;; Get path (default to "/")
    local.get $argc
    i32.const 1
    i32.gt_s
    if
      local.get $argv
      i32.const 4
      i32.add
      i32.load
      local.set $path
    else
      i32.const 2048  ;; "/" string
      local.set $path
    end
    
    ;; Call fs_list
    global.get $buffer_start
    local.set $buffer
    local.get $path
    local.get $buffer
    i32.const 4096
    call $fs_list
    local.set $result
    
    ;; Print result
    local.get $result
    i32.const 0
    i32.gt_s
    if
      local.get $buffer
      local.get $result
      call $print
    else
      i32.const 256  ;; "Error: "
      i32.const 7
      call $print
      i32.const 512  ;; "No such file or directory\n"
      i32.const 27
      call $print
    end
    
    local.get $result
    i32.const 0
    i32.ge_s
  )

  ;; Cat command
  (func $cat (export "cat") (param $argc i32) (param $argv i32) (result i32)
    (local $path i32)
    (local $fd i32)
    (local $buffer i32)
    (local $bytes_read i32)
    
    ;; Check arguments
    local.get $argc
    i32.const 2
    i32.lt_s
    if
      ;; Print usage
      i32.const 64
      i32.const 7
      call $print
      i32.const 0
      return
    end
    
    ;; Get file path
    local.get $argv
    i32.const 4
    i32.add
    i32.load
    local.set $path
    
    ;; Open file
    local.get $path
    i32.const 0  ;; O_RDONLY
    call $fs_open
    local.tee $fd
    i32.const 0
    i32.lt_s
    if
      ;; Error opening file
      i32.const 256
      i32.const 7
      call $print
      i32.const 512
      i32.const 27
      call $print
      i32.const 1
      return
    end
    
    ;; Read and print file
    global.get $buffer_start
    local.set $buffer
    loop
      local.get $fd
      local.get $buffer
      i32.const 4096
      call $fs_read
      local.tee $bytes_read
      i32.const 0
      i32.gt_s
      if
        local.get $buffer
        local.get $bytes_read
        call $print
        br 1
      end
    end
    
    ;; Close file
    local.get $fd
    call $fs_close
    drop
    
    i32.const 0
  )

  ;; Pwd command
  (func $pwd (export "pwd") (param $argc i32) (param $argv i32) (result i32)
    ;; For now, just print "/"
    i32.const 2048
    i32.const 1
    call $print
    i32.const 128
    i32.const 1
    call $print
    i32.const 0
  )

  ;; Uname command
  (func $uname (export "uname") (param $argc i32) (param $argv i32) (result i32)
    (local $buffer i32)
    
    ;; Store system info in buffer
    global.get $buffer_start
    local.set $buffer
    
    ;; Write "k23" to buffer
    local.get $buffer
    i32.const 0x336b32  ;; "k23" in little endian
    i32.store
    
    ;; Print it
    local.get $buffer
    i32.const 3
    call $print
    
    ;; Print newline
    i32.const 128
    i32.const 1
    call $print
    
    i32.const 0
  )

  ;; Free command
  (func $free (export "free") (param $argc i32) (param $argv i32) (result i32)
    (local $buffer i32)
    
    global.get $buffer_start
    local.set $buffer
    
    ;; Get memory info from host
    local.get $buffer
    call $get_memory_info
    
    ;; Print memory info (simplified output)
    local.get $buffer
    i32.const 256
    call $print
    
    i32.const 0
  )

  ;; Date command
  (func $date (export "date") (param $argc i32) (param $argv i32) (result i32)
    (local $time i64)
    (local $buffer i32)
    
    ;; Get current time
    call $get_time
    local.set $time
    
    ;; Format and print (simplified)
    global.get $buffer_start
    local.set $buffer
    
    ;; Store formatted date string
    local.get $buffer
    i32.const 0x6e614a20  ;; " Jan"
    i32.store
    
    local.get $buffer
    i32.const 32
    call $print
    
    i32.const 128
    i32.const 1
    call $print
    
    i32.const 0
  )

  ;; Whoami command  
  (func $whoami (export "whoami") (param $argc i32) (param $argv i32) (result i32)
    (local $buffer i32)
    
    global.get $buffer_start
    local.set $buffer
    
    ;; Write "root" to buffer
    local.get $buffer
    i32.const 0x746f6f72  ;; "root" in little endian
    i32.store
    
    local.get $buffer
    i32.const 4
    call $print
    
    i32.const 128
    i32.const 1
    call $print
    
    i32.const 0
  )
  
  ;; Main entry point for busybox
  (func $busybox_main (export "busybox_main") (param $argc i32) (param $argv i32) (param $cmd i32) (result i32)
    ;; Dispatch to appropriate command based on cmd parameter
    local.get $cmd
    
    ;; Check command index
    i32.const 0
    i32.eq
    if (result i32)
      local.get $argc
      local.get $argv
      call $echo
      return
    end
    
    local.get $cmd
    i32.const 1
    i32.eq
    if (result i32)
      local.get $argc
      local.get $argv
      call $ls
      return
    end
    
    local.get $cmd
    i32.const 2
    i32.eq
    if (result i32)
      local.get $argc
      local.get $argv
      call $cat
      return
    end
    
    local.get $cmd
    i32.const 3
    i32.eq
    if (result i32)
      local.get $argc
      local.get $argv
      call $pwd
      return
    end
    
    local.get $cmd
    i32.const 4
    i32.eq
    if (result i32)
      local.get $argc
      local.get $argv
      call $uname
      return
    end
    
    local.get $cmd
    i32.const 5
    i32.eq
    if (result i32)
      local.get $argc
      local.get $argv
      call $free
      return
    end
    
    local.get $cmd
    i32.const 6
    i32.eq
    if (result i32)
      local.get $argc
      local.get $argv
      call $date
      return
    end
    
    local.get $cmd
    i32.const 7
    i32.eq
    if (result i32)
      local.get $argc
      local.get $argv
      call $whoami
      return
    end
    
    ;; Unknown command
    i32.const 1
  )
)