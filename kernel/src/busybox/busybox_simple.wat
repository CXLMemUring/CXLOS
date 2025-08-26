;; Simplified BusyBox WASM module
(module
  ;; Import host functions
  (import "host" "print" (func $print (param i32 i32)))
  
  ;; Memory
  (memory 1)
  (export "memory" (memory 0))
  
  ;; Data section
  (data (i32.const 0) "k23\n")
  (data (i32.const 16) "root\n")  
  (data (i32.const 32) "/\n")
  (data (i32.const 48) "Hello from WASM busybox!\n")
  (data (i32.const 80) "bin/ dev/ etc/ home/ lib/ proc/ sys/ tmp/ usr/ var/\n")
  
  ;; Echo command
  (func $echo (export "echo") (result i32)
    i32.const 48
    i32.const 25
    call $print
    i32.const 0
  )
  
  ;; Ls command  
  (func $ls (export "ls") (result i32)
    i32.const 80
    i32.const 53
    call $print
    i32.const 0
  )
  
  ;; Pwd command
  (func $pwd (export "pwd") (result i32)
    i32.const 32
    i32.const 2
    call $print
    i32.const 0
  )
  
  ;; Uname command
  (func $uname (export "uname") (result i32)
    i32.const 0
    i32.const 4
    call $print
    i32.const 0
  )
  
  ;; Whoami command
  (func $whoami (export "whoami") (result i32)
    i32.const 16
    i32.const 5
    call $print
    i32.const 0
  )
)