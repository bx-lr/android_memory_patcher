.text
.global main
            main:
              .arm
                SUB     SP, SP, #8      
                ADR	R0, _filepath     
		LDR	R5, _open
		BLX	R5
		MOVS    R3, #0
		MOVS    R1, #0x80
		MOVS    R4, R0
		LSLS    R1, R1, #3
		STR     R0, [SP] 
		STR     R3, [SP, #4] 
		MOVS    R2, #5          
		MOVS    R3, #1          
		MOVS    R0, #0          
		LDR	R5, _mmap
		BLX	R5
		BKPT
		MOVS    R0, R4          
		LDR	R5, _close
		BLX	R5
		ADD     SP, SP, #8


_open:
.word 0xAFD132B1

_close:
.word 0xAFD0DC90

_mmap:
.word 0xAFD13265

_filepath: 
.string "/data/local/tmp/test.map"

