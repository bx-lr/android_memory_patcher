.text
.global main
            main:
              .arm

		ADR	R0, _txt
		LDR	R5, _printf
		BLX	R5
		B	asdf		


_printf:
.word 0xAFD15DCD

_txt:
.string "w00t!!\n"
.align 1
		asdf:

