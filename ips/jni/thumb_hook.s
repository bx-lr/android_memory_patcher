.text
.global main
            main:
              .thumb
		bx pc
		nop
	      .arm
		LDR	PC, [PC, #-4]
.word
0xaabbccdd
