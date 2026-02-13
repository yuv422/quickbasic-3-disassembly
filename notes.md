# QuickBasic 3 disassembly & reverse engineering notes

<!-- TOC -->
* [QuickBasic 3 disassembly & reverse engineering notes](#quickbasic-3-disassembly--reverse-engineering-notes)
  * [BRUN30.EXE Runtime](#brun30exe-runtime)
  * [DEF FN](#def-fn)
  * [GOSUB](#gosub)
  * [GOTO](#goto)
  * [INP](#inp)
  * [Temp variables](#temp-variables)
  * [BASIC Compiled interrupt functions](#basic-compiled-interrupt-functions)
  * [0x3d Interrupt](#0x3d-interrupt)
    * [0x1 - FIX (float)](#0x1---fix-float)
    * [0x2 - FIX (double)](#0x2---fix-double)
    * [0x3 - INT (float)](#0x3---int-float)
    * [0x4 - INT (double)](#0x4---int-double)
    * [0x5 - CHR$](#0x5---chr)
    * [0x6 - INKEY$](#0x6---inkey)
    * [0x7 - INPUT$](#0x7---input)
    * [0x9 - INSTR](#0x9---instr)
    * [0xA - MID$](#0xa---mid)
    * [0xB - LEFT$](#0xb---left)
    * [0xC - RIGHT$](#0xc---right)
    * [0xD - SPACE$](#0xd---space)
    * [0xE - STRING$ (m.n)](#0xe---string-mn)
    * [0xF - STRING$ (m,string)](#0xf---string-mstring)
    * [0x11 - STR$](#0x11---str)
    * [0x13 - VAL](#0x13---val)
    * [0x14 - HEX$ (integer)](#0x14---hex-integer)
    * [0x15 - HEX$ (float)](#0x15---hex-float)
    * [0x18 - CVI](#0x18---cvi)
    * [0x19 - CVS](#0x19---cvs)
    * [0x1A - CVD](#0x1a---cvd)
    * [0x1B - MKI$](#0x1b---mki)
    * [0x1C - MKS$](#0x1c---mks)
    * [0x1D - MKD$](#0x1d---mkd)
    * [0x1E - ERL](#0x1e---erl)
    * [0x1F - ERR](#0x1f---err)
    * [0x20 - LPOS](#0x20---lpos)
    * [0x22 - INT (integer)](#0x22---int-integer)
    * [0x23 - DATE$](#0x23---date)
    * [0x24 - TIME$](#0x24---time)
    * [0x25 - CSRLIN](#0x25---csrlin)
    * [0x27 - POINT (x, y)](#0x27---point-x-y)
    * [0x2A - POINT value](#0x2a---point-value)
    * [0x2D - STICK](#0x2d---stick)
    * [0x2E - STRIG](#0x2e---strig)
    * [0x2F - EOF](#0x2f---eof)
    * [0x30 - LOC](#0x30---loc)
    * [0x31 - LOF](#0x31---lof)
    * [0x32 - VARPTR file](#0x32---varptr-file)
    * [0x33 - RND(n)](#0x33---rndn)
    * [0x34 - RND](#0x34---rnd)
    * [0x35 - ATN](#0x35---atn)
    * [0x36 - COS](#0x36---cos)
    * [0x37 - EXP](#0x37---exp)
    * [0x38 - LOG](#0x38---log)
    * [0x39 - SIN](#0x39---sin)
    * [0x3A - SQR](#0x3a---sqr)
    * [0x3B - TAN](#0x3b---tan)
    * [0x3C - ATN (double)](#0x3c---atn-double)
    * [0x3D - COS (double)](#0x3d---cos-double)
    * [0x3E - EXP (double)](#0x3e---exp-double)
    * [0x3F - LOG (double)](#0x3f---log-double)
    * [0x40 - SIN (double)](#0x40---sin-double)
    * [0x41 - SQR (double)](#0x41---sqr-double)
    * [0x42 - TAN (double)](#0x42---tan-double)
    * [0x43 - TIMER](#0x43---timer)
    * [0x45 - IOCTL$](#0x45---ioctl)
    * [0x46 - ENVIRON$ (name)](#0x46---environ-name)
    * [0x47 - ENVIRON$ (ordinal)](#0x47---environ-ordinal)
    * [0x48 - ERDEV](#0x48---erdev)
    * [0x49 - ERDEV$](#0x49---erdev)
    * [0x4A - COMMAND$](#0x4a---command)
    * [0x62 - PEEK](#0x62---peek)
    * [0x63 - FRE (string)](#0x63---fre-string)
    * [0x64 - FRE (num)](#0x64---fre-num)
    * [0x65 - SADD](#0x65---sadd)
  * [0x3e Interrupt](#0x3e-interrupt)
    * [0x1 - END](#0x1---end)
    * [0x2 - (END PROGRAM)](#0x2---end-program)
    * [0x7 - WRITE to device start](#0x7---write-to-device-start)
    * [0x8 - RANDOMIZE (no args)](#0x8---randomize-no-args)
    * [0x9 - RANDOMIZE](#0x9---randomize)
    * [0xB - CLEAR](#0xb---clear)
    * [0xC - CLEAR (no stack args)](#0xc---clear-no-stack-args)
    * [0xE - CHAIN](#0xe---chain)
    * [0x11 - ERROR](#0x11---error)
    * [0x13 - RESUME](#0x13---resume)
    * [0x14 - DEF SEG (default)](#0x14---def-seg-default)
    * [0x15 - DEF SEG](#0x15---def-seg)
    * [0x17 - DATE$ (write)](#0x17---date-write)
    * [0x18 - TIME$ (write)](#0x18---time-write)
    * [0x19 - BLOAD (offset from file)](#0x19---bload-offset-from-file)
    * [0x1A - BLOAD](#0x1a---bload)
    * [0x1B - BSAVE](#0x1b---bsave)
    * [0x1C - FILES](#0x1c---files)
    * [0x1D - FILES (no argument)](#0x1d---files-no-argument)
    * [0x1E - OPEN](#0x1e---open)
    * [0x20 - OPEN mode](#0x20---open-mode)
    * [0x21 - CLOSE](#0x21---close)
    * [0x22 - CLOSE (close all open files)](#0x22---close-close-all-open-files)
    * [0x23 - NAME](#0x23---name)
    * [0x24 - KILL](#0x24---kill)
    * [0x25 - GET (default)](#0x25---get-default)
    * [0x26 - GET](#0x26---get)
    * [0x28 - PUT (File IO)](#0x28---put-file-io)
    * [0x2B - BEEP](#0x2b---beep)
    * [0x32 - CLS](#0x32---cls-)
    * [0x33 - Add argument to COLOR command](#0x33---add-argument-to-color-command)
    * [0x35 - COLOR](#0x35---color)
    * [0x36 - DRAW](#0x36---draw)
    * [0x3B - STEP ??](#0x3b---step-)
    * [0x3C - KEY on/off/list](#0x3c---key-onofflist)
    * [0x3D - KEY](#0x3d---key)
    * [0x42 - LOCATE arg](#0x42---locate-arg)
    * [0x43 - LOCATE arg not supplied](#0x43---locate-arg-not-supplied)
    * [0x44 - LOCATE](#0x44---locate)
    * [0x4A - PALETTE](#0x4a---palette)
    * [0x51 - PLAY](#0x51---play)
    * [0x52 - PLAY ON](#0x52---play-on)
    * [0x53 - PLAY OFF](#0x53---play-off)
    * [0x54 - PLAY STOP](#0x54---play-stop)
    * [0x55 - PRESET (step)](#0x55---preset-step)
    * [0x56 - PSET](#0x56---pset)
    * [0x58 - PUT (graphics)](#0x58---put-graphics)
    * [0x5B - SCREEN](#0x5b---screen)
    * [0x5C - STRIG ON](#0x5c---strig-on)
    * [0x5D - STRIG OFF](#0x5d---strig-off)
    * [0x64 - COM(n) ON](#0x64---comn-on)
    * [0x65 - COM(n) OFF](#0x65---comn-off)
    * [0x66 - COM(n) STOP](#0x66---comn-stop)
    * [0x67 - KEY(n) ON](#0x67---keyn-on)
    * [0x68 - KEY(n) OFF](#0x68---keyn-off)
    * [0x69 - KEY(n) STOP](#0x69---keyn-stop)
    * [0x76 - TIMER ON](#0x76---timer-on)
    * [0x77 - TIMER OFF](#0x77---timer-off)
    * [0x78 - TIMER STOP](#0x78---timer-stop)
    * [0x79 - PRINT](#0x79---print)
    * [0x7D - IOCTL](#0x7d---ioctl)
    * [0x7E - ENVIRON](#0x7e---environ)
    * [0x7F - CHDIR](#0x7f---chdir)
    * [0x84 - LINE (start position)](#0x84---line-start-position)
    * [0x85 - LINE (end position)](#0x85---line-end-position)
    * [0x86 - LINE](#0x86---line)
    * [0x89 - PUT (position)](#0x89---put-position)
    * [0x8A - PRESET](#0x8a---preset)
    * [0x8C - CIRCLE](#0x8c---circle)
    * [0x8D - set point (x, y)](#0x8d---set-point-x-y)
    * [0xA5 - POKE](#0xa5---poke)
  * [0x3f Interrupt](#0x3f-interrupt)
    * [0x2 - ON ERROR trap](#0x2---on-error-trap)
    * [0x4 - ON KEY trap](#0x4---on-key-trap)
    * [0x6 - ON STRIG](#0x6---on-strig)
    * [0x7 - ON TIMER](#0x7---on-timer)
    * [0x8 - ON PLAY trap](#0x8---on-play-trap)
    * [0x9 - RESUME label](#0x9---resume-label)
    * [0xA - RSET](#0xa---rset)
    * [0xD - READ (float)](#0xd---read-float)
    * [0xE - READ (double)](#0xe---read-double)
    * [0xF - READ (integer)](#0xf---read-integer)
    * [0x10 - READ (string)](#0x10---read-string)
    * [0x15 - VARPTR$ float](#0x15---varptr-float)
    * [0x16 - VARPTR$ double](#0x16---varptr-double)
    * [0x17 - VARPTR$ integer](#0x17---varptr-integer)
    * [0x18 - VARPTR$ string](#0x18---varptr-string)
    * [0x19 - float to int](#0x19---float-to-int)
    * [0x1D - float to boolean](#0x1d---float-to-boolean)
    * [0x1E - double to boolean](#0x1e---double-to-boolean)
    * [0x1F - tmpVarFloat to boolean](#0x1f---tmpvarfloat-to-boolean)
    * [0x20 - tmpVarDouble to boolean](#0x20---tmpvardouble-to-boolean)
    * [0x21 - ?? push float to stack](#0x21----push-float-to-stack)
    * [0x23 - Exponentiation Operator (float)](#0x23---exponentiation-operator-float)
    * [0x24 - Exponentiation Operator (double)](#0x24---exponentiation-operator-double)
    * [0x25 - Exponentiation Operator using tempFloatVar (float)](#0x25---exponentiation-operator-using-tempfloatvar-float)
    * [0x26 - Exponentiation Operator using tempDoubleVar (double)](#0x26---exponentiation-operator-using-tempdoublevar-double)
    * [0x2B - ABS (float)](#0x2b---abs-float)
    * [0x2C - ABS (double)](#0x2c---abs-double)
    * [0x2D - ABS (float) temp var](#0x2d---abs-float-temp-var)
    * [0x2E - ABS (double) temp var](#0x2e---abs-double-temp-var)
    * [0x2F - SGN (float)](#0x2f---sgn-float)
    * [0x30 - SGN (double)](#0x30---sgn-double)
    * [0x31 - SGN (float) temp var](#0x31---sgn-float-temp-var)
    * [0x32 - SGN (double) temp var](#0x32---sgn-double-temp-var)
    * [0x39 - start function](#0x39---start-function)
    * [0x3A - end function](#0x3a---end-function)
    * [0x43 - DIM (dynamic float)](#0x43---dim-dynamic-float)
    * [0x44 - DIM (dynamic double)](#0x44---dim-dynamic-double)
    * [0x45 - DIM (dynamic integer)](#0x45---dim-dynamic-integer)
    * [0x46 - DIM (dynamic string)](#0x46---dim-dynamic-string)
    * [0x47 - ERASE float (dynamic)](#0x47---erase-float-dynamic)
    * [0x48 - ERASE double (dynamic)](#0x48---erase-double-dynamic)
    * [0x49 - ERASE int (dynamic)](#0x49---erase-int-dynamic)
    * [0x4A - ERASE str (dynamic)](#0x4a---erase-str-dynamic)
    * [0x4B - ERASE float (static)](#0x4b---erase-float-static)
    * [0x4C - ERASE double (static)](#0x4c---erase-double-static)
    * [0x4D - ERASE int (static)](#0x4d---erase-int-static)
    * [0x4E - ERASE str (static)](#0x4e---erase-str-static)
    * [0x4F - REDIM (float)](#0x4f---redim-float)
    * [0x50 - REDIM (double)](#0x50---redim-double)
    * [0x51 - REDIM (int)](#0x51---redim-int)
    * [0x52 - REDIM (string)](#0x52---redim-string)
    * [0x53 - ?? start subroutine](#0x53----start-subroutine)
    * [0x54 - ?? end subroutine](#0x54----end-subroutine)
    * [0x55 - concatenate strings](#0x55---concatenate-strings)
    * [0x56 - store int as double in temp var](#0x56---store-int-as-double-in-temp-var)
    * [0x57 - store int as float in temp var](#0x57---store-int-as-float-in-temp-var)
    * [0x5B - LSET](#0x5b---lset)
    * [0x5C - MID$ statement](#0x5c---mid-statement)
    * [0x5E - ON GOTO](#0x5e---on-goto)
    * [0x5D - ON GOSUB](#0x5d---on-gosub)
    * [0x60 - RETURN](#0x60---return)
    * [0x61 - Copy string](#0x61---copy-string)
    * [0x62 - Compare strings](#0x62---compare-strings)
    * [0x63 - PRINT (float)](#0x63---print-float)
    * [0x64 - PRINT (double)](#0x64---print-double)
    * [0x65 - PRINT (integer)](#0x65---print-integer)
    * [0x66 - PRINT (string)](#0x66---print-string)
    * [0x67 - PRINT (float) semicolon](#0x67---print-float-semicolon)
    * [0x68 - PRINT (double) semicolon](#0x68---print-double-semicolon)
    * [0x69 - PRINT (integer) semicolon](#0x69---print-integer-semicolon)
    * [0x6A - PRINT (string) semicolon](#0x6a---print-string-semicolon)
    * [0x6B - PRINT (float) newline](#0x6b---print-float-newline)
    * [0x6C - PRINT (double) newline](#0x6c---print-double-newline)
    * [0x6D - PRINT (integer) newline](#0x6d---print-integer-newline)
    * [0x6E - PRINT (string) newline](#0x6e---print-string-newline)
    * [0x6F - PUSH float](#0x6f---push-float)
    * [0x71 - Push float temp var onto stack (3 param)](#0x71---push-float-temp-var-onto-stack-3-param)
    * [0x72 - Push double temp var onto stack (3 param)](#0x72---push-double-temp-var-onto-stack-3-param)
    * [0x74 - ?? convert float temp var to double temp var](#0x74----convert-float-temp-var-to-double-temp-var)
    * [0x73 - store float as double in temp var](#0x73---store-float-as-double-in-temp-var)
    * [0x75 - CINT (float)](#0x75---cint-float)
    * [0x76 - CINT (double)](#0x76---cint-double)
    * [0x77 - pop integer off stack](#0x77---pop-integer-off-stack)
    * [0x78 - POP double as integer ??](#0x78---pop-double-as-integer-)
    * [0x79 - CSNG](#0x79---csng)
    * [0x7A - convert temp vart from double to float](#0x7a---convert-temp-vart-from-double-to-float)
    * [0x7B - Copy float from one var to another](#0x7b---copy-float-from-one-var-to-another)
    * [0x7C - Copy double from one var to another](#0x7c---copy-double-from-one-var-to-another)
    * [0x7D - POP float](#0x7d---pop-float)
    * [0x7E - POP double](#0x7e---pop-double)
    * [0x7F - Addition (float)](#0x7f---addition-float)
    * [0x80 - Addition (double)](#0x80---addition-double)
    * [0x81 - Addition temp var + DI (float)](#0x81---addition-temp-var--di-float)
    * [0x82 - Addition temp var + DI (double)](#0x82---addition-temp-var--di-double)
    * [0x83 - Addition temp var + SI (float)](#0x83---addition-temp-var--si-float)
    * [0x84 - Addition temp var + SI (double)](#0x84---addition-temp-var--si-double)
    * [0x85 - Addition stack + temp var (float) (3 param)](#0x85---addition-stack--temp-var-float-3-param)
    * [0x86 - Addition stack + temp var (double) (3 param)](#0x86---addition-stack--temp-var-double-3-param)
    * [0x87 - Division (float)](#0x87---division-float)
    * [0x88 - Division (double)](#0x88---division-double)
    * [0x89 - Division tmpVarFloat by float DI](#0x89---division-tmpvarfloat-by-float-di)
    * [0x8A - Division tmpVarDouble by double DI](#0x8a---division-tmpvardouble-by-double-di)
    * [0x8B - Division float SI by tmpVarFloat](#0x8b---division-float-si-by-tmpvarfloat)
    * [0x8C - Division double SI by tmpVarDouble](#0x8c---division-double-si-by-tmpvardouble)
    * [0x8f - Multiplication (float)](#0x8f---multiplication-float)
    * [0x90 - Multiplication (double)](#0x90---multiplication-double)
    * [0x91 - Multiplication float tmpVarFloat DI](#0x91---multiplication-float-tmpvarfloat-di)
    * [0x92 - Multiplication double tmpVarDouble DI](#0x92---multiplication-double-tmpvardouble-di)
    * [0x93 - Multiplication float tmpVarFloat SI](#0x93---multiplication-float-tmpvarfloat-si)
    * [0x94 - Multiplication double tmpVarDouble SI](#0x94---multiplication-double-tmpvardouble-si)
    * [0x95 - Multiplication stack * temp var (float) (3 param)](#0x95---multiplication-stack--temp-var-float-3-param)
    * [0x96 - Multiplication stack * temp var (double) (3 param)](#0x96---multiplication-stack--temp-var-double-3-param)
    * [0x97 - Subtraction (float)](#0x97---subtraction-float)
    * [0x98 - Subtraction (double)](#0x98---subtraction-double)
    * [0x99 - Subtraction temp var - (float)](#0x99---subtraction-temp-var---float)
    * [0x9A - Subtraction temp var - (double)](#0x9a---subtraction-temp-var---double)
    * [0x9B - Subtraction (float) - temp var](#0x9b---subtraction-float---temp-var)
    * [0x9C - Subtraction (double) - temp var](#0x9c---subtraction-double---temp-var)
    * [0x9D - Subtract tmpVarFloat from floatStackValue (3 param)](#0x9d---subtract-tmpvarfloat-from-floatstackvalue-3-param)
    * [0x9E - Subtract tmpVarFloat from doubleStackValue (3 param)](#0x9e---subtract-tmpvarfloat-from-doublestackvalue-3-param)
    * [0x9F - compare floats](#0x9f---compare-floats)
    * [0xA0 - compare doubles](#0xa0---compare-doubles)
    * [0xA1 - compare float to temp var](#0xa1---compare-float-to-temp-var)
    * [0xA2 - compare double to temp var](#0xa2---compare-double-to-temp-var)
    * [0xA5 - Compare tmpVarFloat and stack float value](#0xa5---compare-tmpvarfloat-and-stack-float-value)
    * [0xA7 - compare float with zero](#0xa7---compare-float-with-zero)
    * [0xA8 - compare double with zero](#0xa8---compare-double-with-zero)
    * [0xA9 - compare tmpVarFloat with zero](#0xa9---compare-tmpvarfloat-with-zero)
    * [0xAA - compare tmpVarDouble with zero](#0xaa---compare-tmpvardouble-with-zero)
    * [0xAB - multiply float by power of 2](#0xab---multiply-float-by-power-of-2)
    * [0xAC - multiply double by power of 2](#0xac---multiply-double-by-power-of-2)
    * [0xAD - multiply tmpVarFloat by power of 2](#0xad---multiply-tmpvarfloat-by-power-of-2)
    * [0xAE - multiply tmpVarDouble by power of 2](#0xae---multiply-tmpvardouble-by-power-of-2)
    * [0xAF - float negation](#0xaf---float-negation)
    * [0xB0 - double negation](#0xb0---double-negation)
    * [0xB3 - ?? FIELD start maybe](#0xb3----field-start-maybe)
    * [0xB4 - FIELD var](#0xb4---field-var)
    * [0xB5 - INPUT from keyboard](#0xb5---input-from-keyboard)
    * [0xB6 - INPUT file/device](#0xb6---input-filedevice)
    * [0xB7 - INPUT arguments](#0xb7---input-arguments)
    * [0xB8 - INPUT load variable value](#0xb8---input-load-variable-value)
    * [0xBA - LEN](#0xba---len)
    * [0xBC - print to screen start](#0xbc---print-to-screen-start)
    * [0xBD - PRINT USING](#0xbd---print-using)
    * [0xBE - PRINT \#](#0xbe---print-)
    * [0xBB - ASC](#0xbb---asc)
<!-- TOC -->

## BRUN30.EXE Runtime

## DEF FN
Functions are `CALL`'d and return with `RET` The return value is pushed onto the stack.

## GOSUB
Like functions, gosub is converted into an assembly CALL and RET

eg.

```basic
CLOSE
GOSUB MySub
CLOSE
END

MySub:
PRINT "hello"
RETURN
```

```asm
       1000:0040 cd  3e           INT        0x3e
       1000:0042 22              ??         22h    "                    CLOSE
       1000:0043 e8  06  00       CALL       MySub                      GOSUB MySub
       1000:0046 cd  3e           INT        0x3e
       1000:0048 22              ??         22h    "                    CLOSE
       1000:0049 cd  3e           INT        0x3e
       1000:004b 01              ??         01h                         END
       *************************************************************
       *                          SUBROUTINE                        
       *************************************************************
       MySub
       1000:004c cd  3f           INT        0x3f
       1000:004e bc              ??         BCh
       1000:004f bb  56  18       MOV        BX ,0x1856                 "hello"
       1000:0052 cd  3f           INT        0x3f
       1000:0054 6e              ??         6Eh    n
       1000:0055 cd  3e           INT        0x3e
       1000:0057 79              ??         79h    y                    PRINT "hello"
       1000:0058 c3              RET

```
## GOTO
goto is converted into a `JMP` instruction

## INP
Returns a byte from a specified I/O port. `y = INP(port)`

compiles down to assembly. using `IN` command

eg. `a% = INP(42)` becomes
```asm
       1000:0040 ba  2a  00       MOV        DX ,0x2a
       1000:0043 ec               IN         AL ,DX
       1000:0044 30  e4           XOR        AH ,AH
       1000:0046 a3  56  18       MOV        [0x1856 ],AX
```

## Temp variables
Some operations require an internal temporary variable.

These live at
- `DS:1A` for float values
- `DS:16` for double values

## BASIC Compiled interrupt functions

Basic code is compiled into assembly with the original BASIC code converted into
interrupt calls. Three different types of interrupts are used. 0x3d, 0x3e, 0x3f
The handlers for these custom interrupts live in the Runtime file.

Interrupts take an argument byte which is stored immediately after the int call.

eg. This is the command `SCREEN 7`
```asm
MOV BX, 7
INT 0x3e
db 0x5B
```
This sets the screen into mode 7 which is 320x200 16 colors

Basic code starts at 1000:40 in the EXE. (assuming a base segment of 1000)

## 0x3d Interrupt

### 0x1 - FIX (float)
floor float and push result onto stack

Input:

    BX - pointer to float value

### 0x2 - FIX (double)
floor double and push result onto stack

Input:

    BX - pointer to double value

### 0x3 - INT (float)
Next Lower Integer. result stored in tmpVarFloat

Input:

    BX - pointer to float

### 0x4 - INT (double)
Next Lower Integer. result stored in tmpVarDouble

Input:

    BX - pointer to double

### 0x5 - CHR$
Convert ASCII Code to Character
`s$ = CHR$(code)`

Input:

    BX - contains the integer value

Return:

    BX - string - pointer to string representation of code

### 0x6 - INKEY$
Loads last keypress

Returns:

    BX - pointer to string containing last keypress

### 0x7 - INPUT$
Read Specified Number of Characters
`INPUT$(n [,[#]filenum])`

Input:

    BX - number of characters to read
    DX - filename - or 0x7fff when filenum not supplied. In this case it reads from keyboard.

### 0x9 - INSTR
`INSTR(stringexp1,stringexp2)`

Returns the character position within a string at which a substring is
found.

Input:

    BX - stringexp1 - string to search
    DX - stringexp2 - substring to match

Return:

    BX - integer value of offset. 1 based. 0 = no match

### 0xA - MID$
Substring in Middle
`s$ = MID$(stringexpr,n[,length])`

Input:

    BX - stringexpr - pointer to string
    CX - length - integer value length = 0x7ffff when not supplied
    DX - n - integer value. Offset in string to start copying from.

### 0xB - LEFT$
Substring at Left. Left most n chars.
`s$ = LEFT$(stringexpr,n)`

Input:

    BX - stringexpr - pointer to string
    DX - n - integer value

### 0xC - RIGHT$
Substring at Right. Right most n chars.
`s$ = RIGHT$(stringexpr,n)`

Input:

    BX - stringexpr - pointer to string
    DX - n - integer value

### 0xD - SPACE$
String of n Spaces
`s$ = SPACE$(n)`

Input:

    BX - n - number of spaces - integer value

Return:

    BX - pointer to output string

### 0xE - STRING$ (m.n)
String of Specified Length and Character
`s$ = STRING$(m,n)`

Input:

    BX - m - length of string
    DX - n - char to repeat to make the string. (0 - 255)

Return:

    BX - string - pointer to string

### 0xF - STRING$ (m,string)
String of Specified Length and Character
`newStr$ = STRING$(m,s$)`

Input:

    BX - m - length of string
    DX - s - string pointer to string. First char is repeated into the new string

Return:

    BX - string - pointer to string

### 0x11 - STR$
String Representation of Numeric Expression

Input:

    BX - float - pointer to float

Return:

    BX - pointer to string

### 0x13 - VAL
convert string into double. result stored as double temp var

Input:

    BX - string - pointer to input string

### 0x14 - HEX$ (integer)
Hexadecimal Value, as String. `s$ = HEX$(numexpr)`
Input:

    BX - integer value

Returns:

    BX - pointer to hex string

### 0x15 - HEX$ (float)
Hexadecimal Value, as String. `s$ = HEX$(numexpr)`
Input:

    BX - pointer to float

Returns:

    BX - pointer to hex string

### 0x18 - CVI
Convert String to Integer. Result stored in internal integer

Input:

    BX - pointer to string

### 0x19 - CVS
Convert String to float. Result stored in internal float

Input:

    BX - pointer to string

### 0x1A - CVD
Convert String to Double-Precision. Result stored in internal double

Input:

    BX - pointer to string

### 0x1B - MKI$
Convert Integer to String. Result stored in internal string (2 bytes)

Input:

    BX - integer value

### 0x1C - MKS$
Convert float to String. Result stored in internal string (4 bytes)

Input:

    BX - pointer to float value

### 0x1D - MKD$
Convert Double-Precision to String. Result stored in internal string

Input:

    BX - pointer to double precision number

### 0x1E - ERL
Line Number of Most Recent Error

Pushes result as float to stack

### 0x1F - ERR
Returns the error number of the most recent runtime error.

Results:

    BX - errorNumber - integer

### 0x20 - LPOS
get position of print head.
`a = LPOS(1)`

Input:

    BX - n - number of printer - integer value

Return:

    BX - position integer value

### 0x22 - INT (integer)
Returns the integer portion of a numeric expression. Result stored in internal integer.

Input:

    BX - integer value

Return:

    BX - integer value

### 0x23 - DATE$
Loads system date into internal string. Date is in the format "MM-DD-YYYY"

### 0x24 - TIME$
Loads system time into internal string. Time is in the format "HH:MM:SS"

Return:

    BX - pointer to string

### 0x25 - CSRLIN
Line Position of Cursor.

Return:

    BX - linPos - integer value

### 0x27 - POINT (x, y)
Get Attribute for point on screen

Input:

    BX - x - integer value
    DX - y - integer value

Return:

    BX - attribute - integer value

### 0x2A - POINT value
Get value at screen location. Stored as a float in temp var.


Input:

    BX - n - integer value
        n = 0 the current physical x coordinate.
        n = 1 the current physical y coordinate.
        n = 2 the current world x coordinate, if WINDOW is
              active; otherwise, the current physical x coordinate.
        n = 3 the current world y coordinate, if WINDOW is
              active; otherwise, the current physical y coordinate.
    DX - unknown - seems to be set to the integer value 0x7fff
### 0x2D - STICK
return Joystick Coordinates
`y = STICK(n)`

Input:

    BX - n - integer value.
                A numeric expression in the range 0 to 3. Determines what
                kind of information is returned, as follows:

                0   Returns x coordinate of joystick A. A STICK(0) call
                    must be performed before STICK(1), STICK(2), or
                    STICK(3) can be used.
                1   Returns the y coordinate of joystick A.
                2   Returns the x coordinate of joystick B.
                3   Returns the y coordinate of joystick B.

Return:

    BX - returnValue - Integer value

### 0x2E - STRIG
Status of Joystick Buttons
`STRIG(n)`
Input:

    BX - n - integer value in the range 0 to 3. Determines the
                kind of information returned, as follows:

                0   Returns -1 if button A has been pressed since the most
                    recent STRIG(0) call; otherwise, returns 0.
                1   Returns -1 if button A is currently pressed; otherwise
                    returns 0.
                2   Returns -1 if button B has been pressed since the most
                    recent STRIG(2) call; otherwise returns 0.
                3   Returns -1 if button B is currently pressed; otherwise
                    returns 0.
Return:

    BX - returnValue - Integer value

### 0x2F - EOF
Checks for end of file.
eg. `y = EOF(filenum)`

Input:

    BX - filenum - integer containing file handle

Returns:

    BX - status - integer containing status. EOF returns -1
                (true); otherwise, it returns 0 (false).

### 0x30 - LOC
Return current position in file. Puts position in double temp var

Input:

    BX - filenum - integer value

### 0x31 - LOF
Return length of file. Puts length in double temp var.

Input:

    BX - filenum - integer value

### 0x32 - VARPTR file
Returns the address of the file handle in memory
`a = VARPTR(#1)`

Input:

    BX - filenum - integer value

Return:

    BX - address - integer value

### 0x33 - RND(n)
Return random number into temp var as float

Input:

    BX - n - pointer to float value
        If n > 0 - next value in sequence
           n = 0 - last value in sequence
           n < 0 - use n to re-seed generator and return first new value in sequence

### 0x34 - RND
Return next random number into temp var as float

### 0x35 - ATN
Calculate arctangent and store internally. Result stored in temp var as float.

Input:
    BX - angle in radians - pointer to float

### 0x36 - COS
Calculate cosine and store internally

Input:
    BX - angle in radians - pointer to float

### 0x37 - EXP
Returns e (the base of natural logarithms) to the power of supplied numexpr.

Pushes result to stack

Input:

    BX - numexpr - pointer to float

### 0x38 - LOG
Calculate natural logarithm and store internally. Result stored in temp var as float.

Input:
    BX - numexpr - pointer to float

### 0x39 - SIN
Calculate sine and store internally. Result stored in temp var as float.

Input:
    BX - angle in radians - pointer to float

### 0x3A - SQR
Calculate square root and store internally. Result stored in temp var as float.

Input:
    BX - numexpr - pointer to float

### 0x3B - TAN
Calculate tangent and store internally. Result stored in temp var as float.

Input:
    BX - angle in radians - pointer to float

### 0x3C - ATN (double)
Calculate arctangent and store internally. Result stored in temp var as double.

Input:
    BX - angle in radians - pointer to double

### 0x3D - COS (double)
Calculate cosine and store internally

Input:
BX - angle in radians - pointer to double

### 0x3E - EXP (double)
Returns e (the base of natural logarithms) to the power of supplied numexpr.

Pushes result to stack

Input:

    BX - numexpr - pointer to double

### 0x3F - LOG (double)
Calculate natural logarithm and store internally. Result stored in temp var as double.

Input:
    BX - numexpr - pointer to double

### 0x40 - SIN (double)
Calculate sine and store internally. Result stored in temp var as double.

Input:
    BX - angle in radians - pointer to double

### 0x41 - SQR (double)
Calculate square root and store internally. Result stored in temp var as double.

Input:
    BX - numexpr - pointer to double

### 0x42 - TAN (double)
Calculate tangent and store internally. Result stored in temp var as double.

Input:
    BX - angle in radians - pointer to double

### 0x43 - TIMER
Loads number of seconds since midnight into temp var DS:1A as integer value

### 0x45 - IOCTL$
Read Control String from Device Driver
`s$ = IOCTL$([#]filenum)`

Input:

    BX - filenum - integer value

Return:

    BX - string - pointer to control string

### 0x46 - ENVIRON$ (name)
Fetch value from system environment table.
eg. `path$ = ENVIRON$("PATH")`

Input:

    BX - envName - pointer to string containing env name

Returns:

    BX - pointer to string containing env value.

### 0x47 - ENVIRON$ (ordinal)
Fetch value from system environment table by number.
eg. `envValue$ = ENVIRON$(1)`

Input:

    BX - ordinal - integer value of index to env table entry to fetch

Returns:

    BX - pointer to string containing env value.

### 0x48 - ERDEV
Critical Error Code

Result:

    BX - errorCode - integer containing error code

### 0x49 - ERDEV$
Device Causing Critical Error

Result:

    BX - deviceName - pointer to string containing device name

### 0x4A - COMMAND$
loads command line into internal string.

### 0x62 - PEEK
Reads a byte from memory address.

Input:
    BX - address - pointer to float containing memory address to read from

Result:
    BX - byte read from memory (0 - 255)

### 0x63 - FRE (string)
Available Memory.
This instruction will cleanup unused strings int the string data space.

Available free memory (in bytes) pushed to stack as a float

Input:
    BX - string - pointer to string

### 0x64 - FRE (num)
Available Memory.
Available free memory (in bytes) pushed to stack as a float

Input:

    BX - num - integer value. 
            -1, QuickBASIC reports the
                size in bytes of the largest free LNA (large numeric
                array) entry.
            Any other number, QuickBASIC omits
                the housecleaning step and reports the amount of free
                space available.

### 0x65 - SADD
Returns the address of a string expression. Set as integer in temp var
`SADD(strexpr)`

Input:

    BX - strexpr - pointer to string

----
0x3e Interrupt
----
Seems to be used for commands.

### 0x1 - END
Terminate Program

### 0x2 - (END PROGRAM)
Found at the end of the program. Clean up and exit to DOS

### 0x7 - WRITE to device start
Start writing to file.
eg `WRITE #2, name$`

Input:

    BX - filenum

### 0x8 - RANDOMIZE (no args)
Prompt the user to enter a random number to seed the RND function

### 0x9 - RANDOMIZE
Seed random number generator with seed value
`RANDOMIZE 42`

Input:

    BX - seed - integer value

### 0xB - CLEAR
Close Files, Reset Variables, Set Stack Space

eg. `CLEAR , 512, 768`

Input:

    BX - first stack argument - integer value
    DX - second stack argument - integer value

### 0xC - CLEAR (no stack args)
Close Files, Reset Variables, Set Stack Space

### 0xE - CHAIN
Chain to another program

Input:

    BX - filespec - pointer to string filename (.EXE extension can be omitted)

### 0x11 - ERROR
Force Error

Input:

    BX - errorCode - integer containing error code

### 0x13 - RESUME
Resume on next instruction after error line.

### 0x14 - DEF SEG (default)
returns the DEF SEG address to default value (`DS`).

### 0x15 - DEF SEG
Specifies the segment address from which arguments to BLOAD, BSAVE,
CALL ABSOLUTE, PEEK, and POKE will be offset.

Argument is passed on the stack. As a float.

### 0x17 - DATE$ (write)
Set the system date

Input:

    BX - newdate - pointer to string containing new date in format "MM-DD-YYYY" or "MM-DD-YY"

### 0x18 - TIME$ (write)
Set the system time

Input:

    BX - newtime - pointer to string containing new time in format "HH:MM:SS"


### 0x19 - BLOAD (offset from file)
Loads a specified memory image file into memory.

Input:

    BX - filespec - pointer to string filename

### 0x1A - BLOAD
Loads a specified memory image file into memory.

Input:

    BX - filespec - pointer to string filename
    DX - offset - pointer to float in the range 0 to 1048575

### 0x1B - BSAVE
Copies a specified portion of memory to a specified file.

Input:

    BX - filespec - pointer to string filename
    DX - offset - pointer to float in the range 0 to 1048575
    CX - length - 1 to 65535

### 0x1C - FILES
Displays a directory listing given in fileSpec.

Input:

    BX - fileSpec - pointer to string holding directory name to display

### 0x1D - FILES (no argument)
Displays a directory listing of current working directory.

### 0x1E - OPEN
Open a file or device for input/output

*TODO* figure out all the arguments
Input:
    BX - fileNum - integer
    DX - filename - pointer to string filename
    CX - length - integer

### 0x20 - OPEN mode
Used to set the file IO mode in the subsequent OPEN command
```asm
       1000:0040 bb  02  00       MOV        BX ,0x2
       1000:0043 cd  3e           INT        0x3e
       1000:0045 20              ??         20h     
       1000:0046 bb  01  00       MOV        BX ,0x1
       1000:0049 ba  5a  18       MOV        DX ,0x185a
       1000:004c 33  c9           XOR        CX ,CX
       1000:004e cd  3e           INT        0x3e
       1000:0050 1e              ??         1Eh
```
Input:

    BX - mode - file io mode
        0 - INPUT
        1 - OUTPUT
        2 - RANDOM (default)
        3 - APPEND

### 0x21 - CLOSE
Close File or Device

Input:

    BX - filenum - integer value

### 0x22 - CLOSE (close all open files)
Close File or Device

### 0x23 - NAME
Rename file

`NAME oldname AS newname`

Input:

    BX - oldname - pointer to string containing old filename
    DX - newname - pointer to string containing new filename

### 0x24 - KILL
delete file

Input:

    BX - pointer to string containing filename

### 0x25 - GET (default)
Read Random File into Buffer

Input:

    BX - filenum - integer value - file handle

### 0x26 - GET
Read Random File into Buffer

`GET #1, 42`

Input:

    BX - filenum - integer value - file handle
    DX - recordNumber - integer value

### 0x28 - PUT (File IO)
Write data to file

Input:

    BX - filenum - integer value
    DX - recordNumber - integer

### 0x2B - BEEP
Sounds the speaker at 800 Hz for a quarter of a second (equivalent to
`PRINT CHR$(7)`).

### 0x32 - CLS 
Clear screen

Input: BX

### 0x33 - Add argument to COLOR command

Input:

    BX - arg - integer value

### 0x35 - COLOR
Set Foreground, Background, and Border Colors

Input:

    BX - last argument - integer value

### 0x36 - DRAW
Draws an object according to instructions specified as a string expression.

eg. `DRAW "R10 D10 R20"`

Input:

    BX - drawInstructions - string pointer to draw instructions

### 0x3B - STEP ??
Seems to indicate the STEP instruction in a line statement.

### 0x3C - KEY on/off/list
Display soft keys on bottom of screen. Or as list

Input:

    BX - command - integer value. 0 = OFF, 1 = ON, 2 = LIST

### 0x3D - KEY
Set soft Keys
`KEY n, strexpr`

Input:

    BX - n - integer value (1 - 10)
    DX - strexpr - pointer to string

### 0x42 - LOCATE arg
Supply an argument to locate command

Input:

    BX - arg - integer value

### 0x43 - LOCATE arg not supplied
Used to indicate that an argument wasn't supplied and the previous value should be used instead.

### 0x44 - LOCATE
LOCATE command. This also contains the last command argument

Input:

    BX - arg - integer value

### 0x4A - PALETTE
Change Color in the Palette
`PALETTE [attribute, color]`

Input:

    BX - attribute - integer
    DX - color - integer

### 0x51 - PLAY
Plays a melody according to instructions specified as a string
expression.
`PLAY s$`

Input:

    BX - s - pointer to string containing music instructions

### 0x52 - PLAY ON
Enable music trap

### 0x53 - PLAY OFF
Disable music trap

### 0x54 - PLAY STOP
PLAY STOP inhibits trapping. QuickBASIC continues checking
the buffer, and if the notes remaining are fewer than
specified in the ON PLAY statement, a subsequent PLAY ON
results in an immediate trap.

### 0x55 - PRESET (step)
Draw Point on Screen using STEP (relative to last graphics point)

Input:

    BX - x - integer
    DX - y - integer
    CX - color

### 0x56 - PSET
Draw point on screen
`PSET [STEP] (x,y) [,color]`

Input:

    BX - x - integer
    DX - y - integer
    CX - color, 0xffff for default color
    
### 0x58 - PUT (graphics)
Plot Array Image on Screen
`PUT (x,y), array [,action]`

Input:

    BX - pointer to array
    DX - action - transform pixel data when writing to screen
        0 - OR
        1 - AND
        2 - PRESET
        3 - PSET
        4 - XOR (default)

### 0x5B - SCREEN
Setup screen mode

`SCREEN [mode][,[colorflag]][,[apage]][,[vpage]]`

`mode` passed in `BX`

### 0x5C - STRIG ON
Enable/Disable the STRIG Function

### 0x5D - STRIG OFF
Disable the STRIG Function. Has unknown second command byte.

```asm
       1000:004f cd  3e           INT        0x3e
       1000:0051 5d              db         5Dh
       1000:0052 cc              ??         CCh
```

### 0x64 - COM(n) ON
Enable COM port n

Input:

    BX - com port number - integer value

### 0x65 - COM(n) OFF
Disable COM port n

Input:

    BX - com port number - integer value

### 0x66 - COM(n) STOP
Disables trapping, but QB continues checking for
activity at the specified communications port.

Input:

    BX - com port number - integer value

### 0x67 - KEY(n) ON
Enable key trap
`KEY(n) ON`

Input:

    BX - n - key to trap (1 - 20)

### 0x68 - KEY(n) OFF
Enable key trap
`KEY(n) OFF`

Input:

    BX - n - key to trap (1 - 20)

### 0x69 - KEY(n) STOP
Enable key trap
`KEY(n) STOP`

Input:

    BX - n - key to trap (1 - 20)

### 0x76 - TIMER ON
Enable timer event trapping

### 0x77 - TIMER OFF
Disable timer event trapping

### 0x78 - TIMER STOP
Disable timer event trapping by continue to check

Also disables trapping, but QB continues checking. If the
specified amount of time has elapsed, a subsequent TIMER
ON results in an immediate trap (provided an ON TIMER
statement with a nonzero line number has been executed).

### 0x79 - PRINT
Displays one or more numeric or string expressions on screen.

Typical usage
```aiignore
INT 0x3f
0xBC
...
load expressions with INT 0x3f calls
...
INT 0x3e
0x79
```

### 0x7D - IOCTL
Send Control String to Device Driver
`IOCTL[#]filenum,stringexpr`

Input:

    BX - filenum
    DX - pointer to stringexpr

### 0x7E - ENVIRON
Set environment variable

eg. `ENVIRON "PATH=TEST"`

Input:

    BX - envString - pointer to string containing env command.

### 0x7F - CHDIR
Change working directory

Input:
    BX - pathspec - pointer to string path (max 128 characters)

### 0x84 - LINE (start position)
Position of start of the line.

Input:

    CX - xType - type of x argument. -1 = float, 0 = integer
    AX - yType - type of y argument. -1 = float, 0 = integer
    BX - x - value
    DX - y - value

### 0x85 - LINE (end position)
Position of end of the line.

Input:

    BX - x - integer value
    DX - y - integer value

### 0x86 - LINE
Draws a line or rectangle on the screen.

Input:

    BX - color - integer value
    CX - style - integer value. Fill style for rectangle border
    DX - bf - integer value 
        -1 for line,
         0 for rectangle with border,
         1 for rectangle filled

### 0x89 - PUT (position)
x, y position for top left corner of destination for pixel copy

Input:

    BX - x - integer value
    DX - y - integer value

### 0x8A - PRESET
Draw Point on Screen
`PRESET [STEP] (x,y) [,color]`

Input:

    BX - color

### 0x8C - CIRCLE
`CIRCLE [STEP] (x,y), radius [,[color] [,[start],[end][,aspect]]]`

Draws an ellipse on the screen.
(x, y) seems to be set using INT 0x3E 0x8D 

*TODO* Investigate optional arguments

Input:

    BX - radius - pointer to float

### 0x8D - set point (x, y)

Input:

    CX - xType - type of x argument. -1 = float, 0 = integer
    AX - yType - type of y argument. -1 = float, 0 = integer
    BX - x - integer value
    DX - y - integer value

### 0xA5 - POKE
Write byte to address in memory

Input:

    BX - address - pointer to float containing address to write to
    DX - byte to write to memory (0 - 255)

---
## 0x3f Interrupt

Seems to be used for variables

### 0x2 - ON ERROR trap
Enable Error Trapping
`ON ERROR GOTO {linenum | linelabel}`

Input:

    DX - jumpTargetAddr - offset to jump to in current segment. eg. CS:jumpTargetAddr

### 0x4 - ON KEY trap
Trap for keypress
`ON KEY(n) GOSUB {linenum | linelabel}`

Input:

    BX - n - key number (1 to 20)
    DX - lineNum | line label - Not sure how this is calculated yet. *TODO*

### 0x6 - ON STRIG
Trap for Specified Joystick Button
`ON STRIG(n) GOSUB {linenum | linelabel}`

Input:

    BX - n - integer value
    DX - jumpTargetAddr - offset to jump to in current segment. eg. CS:jumpTargetAddr

### 0x7 - ON TIMER
Trap for Elapsed Time
`ON TIMER(n) GOSUB {linenum | linelabel}`

Input:

    BX - n - pointer to float containing value in seconds
    DX - jumpTargetAddr - offset to jump to in current segment. eg. CS:jumpTargetAddr

### 0x8 - ON PLAY trap
Trap for Background Music Remaining
`ON PLAY(queuelimit) GOSUB {linenum | linelabel}`

Input:

    BX - queueLimit - integer value
    DX - jumpTargetAddr - offset to jump to in current segment. eg. CS:jumpTargetAddr


### 0x9 - RESUME label
Resume from error handler by jumping to label

Input:

    BX - jumpTargetAddr - offset to jump to in current segment. eg. CS:jumpTargetAddr

### 0xA - RSET
Move string into random access FIELD variable. Right justified.

Input:

    BX - RHS pointer to source string
    DX - LHS pointer to field string

### 0xD - READ (float)
Read DATA item into a float

Input:

    DX - pointer to destination float

### 0xE - READ (double)
Read DATA item into a double

Input:

    DX - pointer to destination double

### 0xF - READ (integer)
Read DATA item into an integer

Input:

    DX - pointer to destination integer

### 0x10 - READ (string)
Read DATA item into a string

Input:

    DX - pointer to destination string

### 0x15 - VARPTR$ float
Offset of Variable, in Character Form

Input:

    BX - variable - pointer to variable

Return:

    BX - pointer to string variable

### 0x16 - VARPTR$ double
Offset of Variable, in Character Form

Input:

    BX - variable - pointer to variable

Return:

    BX - pointer to string variable

### 0x17 - VARPTR$ integer
Offset of Variable, in Character Form

Input:

    BX - variable - pointer to variable

Return:

    BX - pointer to string variable

### 0x18 - VARPTR$ string
Offset of Variable, in Character Form

Input:

    BX - variable - pointer to variable

Return:

    BX - pointer to string variable

### 0x19 - float to int
Convert float to int

Input:

    SI - pointer to float

Returns:

    BX - converted int value

### 0x1D - float to boolean
Convert float to boolean.
0 = false any other value = true

Input:

    SI - float - pointer to float to convert

Return:

    BX - boolean integer value. True = -1, False = 0

### 0x1E - double to boolean
Convert double to boolean.
0 = false any other value = true

Input:

    SI - double - pointer to double to convert

Return:

    BX - boolean integer value. True = -1, False = 0

### 0x1F - tmpVarFloat to boolean
Convert tmpVarFloat to boolean.
0 = false any other value = true

Return:

    BX - boolean integer value. True = -1, False = 0

### 0x20 - tmpVarDouble to boolean
Convert tmpVarDouble to boolean.
0 = false any other value = true

Return:

    BX - boolean integer value. True = -1, False = 0

### 0x21 - ?? push float to stack
Push float onto stack. Seen in `DEF SEG = nnnn` where nnnn is a float
```asm
       1000:0040 be  56  18       MOV        SI ,0x1856
       1000:0043 cd  3f           INT        0x3f
       1000:0045 21               ??         21h    !
```

Input:

    SI - pointer to float value

### 0x23 - Exponentiation Operator (float)
The ^ operator performs exponentiation. Result is stored in temp var.

Input:

    SI - float - base
    DI - float - power

### 0x24 - Exponentiation Operator (double)
The ^ operator performs exponentiation. Result is stored in temp var.
eg. SI ^ DI

Input:

    SI - double - base
    DI - double - power

### 0x25 - Exponentiation Operator using tempFloatVar (float)
The ^ operator performs exponentiation using tempFloatVar. Result is stored in temp var.

Input:

    DI - float - power (tempFloatVar is the base)

### 0x26 - Exponentiation Operator using tempDoubleVar (double)
The ^ operator performs exponentiation using tempDoubleVar. Result is stored in temp var.

Input:

    DI - double - power (tempDoubleVar is the base)

### 0x2B - ABS (float)
Absolute value of float. Result stored in temp var

Input:

    SI - pointer to float

### 0x2C - ABS (double)
Absolute value of double. Result stored in temp var

Input:

    SI - pointer to double

### 0x2D - ABS (float) temp var
Absolute value of float in temp var.

### 0x2E - ABS (double) temp var
Absolute value of double in temp var.

### 0x2F - SGN (float)
Sign of float value. Stored in temp var.

 1 if positive
 0 if 0
-1 if negative

Input:
    
    SI - float - pointer to float

### 0x30 - SGN (double)
Sign of double value. Stored in temp var.

1 if positive
0 if 0
-1 if negative

Input:

    SI - double - pointer to double

### 0x31 - SGN (float) temp var
Sign of float value in temp var. Result stored in temp var.

1 if positive
0 if 0
-1 if negative

### 0x32 - SGN (double) temp var
Sign of double value in temp var. Result stored in temp var.

1 if positive
0 if 0
-1 if negative

### 0x39 - start function
Marks the start of a function. Used for DEF FN functions.

### 0x3A - end function
Marks the end of a function. Used for DEF FN functions.

### 0x43 - DIM (dynamic float)
Create dynamic array

Array dimensions are pushed to the stack as Integers (left to right order)

Second byte of data after INT instruction - number of dimensions

eg.
```asm
       1000:0073 b8  02  00       MOV        AX ,0x2
       1000:0076 50              PUSH       AX
       1000:0077 b8  03  00       MOV        AX ,0x3
       1000:007a 50              PUSH       AX
       1000:007b bb  56  19       MOV        BX ,0x1956
       1000:007e cd  3f           INT        0x3f
       1000:0080 43              ??         43h    C
       1000:0081 02              ??         02h
```

Input:

    BX - pointer to array

### 0x44 - DIM (dynamic double)
Create dynamic array

Array dimensions are pushed to the stack as Integers (left to right order)

Second byte of data after INT instruction - number of dimensions


Input:

    BX - pointer to array

### 0x45 - DIM (dynamic integer)
Create dynamic array

Array dimensions are pushed to the stack as Integers (left to right order)

Second byte of data after INT instruction - number of dimensions

Input:

    BX - pointer to array

### 0x46 - DIM (dynamic string)
Create dynamic array

Array dimensions are pushed to the stack as Integers (left to right order)

Second byte of data after INT instruction - number of dimensions

Input:

    BX - pointer to array

### 0x47 - ERASE float (dynamic)
Erase dynamic array

Input:

    DI - pointer to dynamic array

### 0x48 - ERASE double (dynamic)
Erase dynamic array

Input:

    DI - pointer to dynamic array

### 0x49 - ERASE int (dynamic)
Erase dynamic array

Input:

    DI - pointer to dynamic array

### 0x4A - ERASE str (dynamic)
Erase dynamic array

Input:

    DI - pointer to dynamic array

### 0x4B - ERASE float (static)
Erase bytes in array to zero.

Input:

    DI - pointer to array
    CX - number of records to erase

### 0x4C - ERASE double (static)
Erase bytes in array to zero.

Input:

    DI - pointer to array
    CX - number of records to erase

### 0x4D - ERASE int (static)
Erase bytes in array to zero.

Input:

    DI - pointer to array
    CX - number of records to erase

### 0x4E - ERASE str (static)
Erase bytes in array to zero.

Input:

    DI - pointer to array
    CX - number of records to erase

### 0x4F - REDIM (float)
Redimension dynamic array

Array dimensions are pushed to the stack as Integers (left to right order)

Second byte of data after INT instruction - number of dimensions

### 0x50 - REDIM (double)
Redimension dynamic array

Array dimensions are pushed to the stack as Integers (left to right order)

Second byte of data after INT instruction - number of dimensions

### 0x51 - REDIM (int)
Redimension dynamic array

Array dimensions are pushed to the stack as Integers (left to right order)

Second byte of data after INT instruction - number of dimensions

### 0x52 - REDIM (string)
Redimension dynamic array

Array dimensions are pushed to the stack as Integers (left to right order)

Second byte of data after INT instruction - number of dimensions

### 0x53 - ?? start subroutine

### 0x54 - ?? end subroutine

### 0x55 - concatenate strings
Concatenate two strings together
*TODO* check input register use. AX and CX were set in the example
```asm
       1000:0054 8b  da           MOV        BX ,DX
       1000:0056 8b  c1           MOV        AX ,CX
       1000:0058 cd  3f           INT        0x3f
       1000:005a 55               ??         55h    U
```

Input:

    AX - pointer to first string
    BX - pointer to second string

Return:

    BX - pointer to newly concatenated string

### 0x56 - store int as double in temp var
Convert integer value to double and store it in temp storage at DS:16
Used for CDBL(integer expression)

Input:

    BX - integer value

### 0x57 - store int as float in temp var
Convert integer value to float and store it in temp storage at DS:1A

Input:

    BX - integer value

### 0x5B - LSET
Move string into random access FIELD variable. Left justified.

Input:

    BX - RHS pointer to source string
    DX - LHS pointer to field string

### 0x5C - MID$ statement
Assign substring
`MID$(stringvar,n[,length]) = stringexpr`

Input:

    BX - stringexpr - string pointer to src string
    DX - stringvar - string pointer to assignment target string
    CX - n - integer value
    AX - length - integer value, 0x7fff when not supplied

### 0x5E - ON GOTO
Branch to nth Item in Line List
`ON n GOTO addr, [,addr]...`
Total number of addresses and address ptrs are stored after the opcode

eg.
```asm
       1000:004e cd  3f           INT        0x3f
       1000:0050 5e              db         5Eh             I3F_5E_UNK
       1000:0051 03              ??         03h             numAddrs
       1000:0052 4e  00           dw         4Eh
       1000:0054 5d  00           dw         5Dh
       1000:0056 6c  00           dw         6Ch
```
number of addresses stored in byte after opcode
each address is a 2 byte pointer to code CS:ptr

Input:

    BX - n - integer value

### 0x5D - ON GOSUB
Branch to nth Item in subroutine List
`ON n GOSUB addr, [,addr]...`
Total number of addresses and address ptrs are stored after the opcode

each address is a pointer to code CS:ptr

Input:

    BX - n - integer value

### 0x60 - RETURN
RETURN from gosub

### 0x61 - Copy string
Copy string from one var to another

Input:

    BX - pointer to source string
    DX - pointer to destination string

### 0x62 - Compare strings
compare two strings and set x86 flags accordingly

Input:

    AX - pointer to first string
    BX - pointer to second string

Return:

    BX - 0 if strings are equal, non-zero otherwise

### 0x63 - PRINT (float)
Print float to output

Input:

    BX - pointer to float

### 0x64 - PRINT (double)
Print double to output

Input:

    BX - pointer to double

### 0x65 - PRINT (integer)
Print integer to output

Input:

    BX - integer value to print

### 0x66 - PRINT (string)
Print string to output

Input:

    BX - pointer to string

### 0x67 - PRINT (float) semicolon
Print float to output

Input:

    BX - pointer to float

### 0x68 - PRINT (double) semicolon
Print double to output

Input:

    BX - pointer to double

### 0x69 - PRINT (integer) semicolon
Print integer to output

Input:

    BX - integer value to print

### 0x6A - PRINT (string) semicolon
Print string to output

Input:

    BX - pointer to string

### 0x6B - PRINT (float) newline
Print float to output and add new line

Input:

    BX - pointer to float

### 0x6C - PRINT (double) newline
Print double to output and add new line

Input:

    BX - pointer to double

### 0x6D - PRINT (integer) newline
Print integer to output and add new line

Input:

    BX - integer value to print

### 0x6E - PRINT (string) newline
Print string to output and add new line

Input:

    BX - pointer to string

### 0x6F - PUSH float
Push float onto stack.

Input:

    SI - pointer to float value

### 0x71 - Push float temp var onto stack (3 param)
Pushes the current value of float temp var onto a stack.
Has a second byte operand which appears to start at 0x80 and increment with each invocation.

### 0x72 - Push double temp var onto stack (3 param)
Pushes the current value of double temp var onto a stack.
Has a second byte operand which appears to start at 0x80 and increment with each invocation.

### 0x74 - ?? convert float temp var to double temp var

### 0x73 - store float as double in temp var
Convert float value to double and store in temp var

Input:

    SI - pointer to float value

### 0x75 - CINT (float)
Convert float to integer

Input:

    SI - float pointer

Output:

    BX - integer value


### 0x76 - CINT (double)
Convert double to integer

Input:

    SI - double pointer

Output:

    BX - integer value

### 0x77 - pop integer off stack

Returns:

    BX - integer value

### 0x78 - POP double as integer ??
Potentially converts double stack var to integer

Returns:

    BX - integer value

### 0x79 - CSNG
convert double to float and store in internal float

Input:

    SI - double pointer

### 0x7A - convert temp vart from double to float
Convert temp var from double to float. Maybe???

### 0x7B - Copy float from one var to another
eg. `A = 10`

Not sure if anything else is happening in this call.

Input:

    SI - source float pointer
    DI - destination float pointer

### 0x7C - Copy double from one var to another
eg. `A# = 10`

Not sure if anything else is happening in this call.

Input:

    SI - source double pointer
    DI - destination double pointer

### 0x7D - POP float
Returns internal number as a float

Input:

`DI` address of resulting float.

### 0x7E - POP double
Returns internal number as a double

Input:

    DI - address of resulting double.

### 0x7F - Addition (float)
Add two floats together and push result to stack
`PUSH SI + DI`

Input:
    SI - pointer to first float
    DI - pointer to second float

### 0x80 - Addition (double)
Add two doubles together and push result to stack
`PUSH SI + DI`

Input:
SI - pointer to first double
DI - pointer to second double

### 0x81 - Addition temp var + DI (float)
Add float to temp var storing result in temp var

Input:

    DI - float - pointer to float to be added.

### 0x82 - Addition temp var + DI (double)
Add double to temp var storing result in temp var

Input:

    DI - double - pointer to double to be added.

### 0x83 - Addition temp var + SI (float)
Add float to temp var storing result in temp var

Input:

    SI - float - pointer to float to be added.

### 0x84 - Addition temp var + SI (double)
Add double to temp var storing result in temp var

Input:

    SI - double - pointer to double to be added.

### 0x85 - Addition stack + temp var (float) (3 param)
Has second byte seems to start at 0x80 and increment for each call to op
Result of addition is stored in temp var

### 0x86 - Addition stack + temp var (double) (3 param)
Has second byte seems to start at 0x80 and increment for each call to op
Result of addition is stored in temp var


### 0x87 - Division (float)
Dived two floats and push result to stack
`PUSH SI / DI`

Input:
SI - pointer to first float
DI - pointer to second float

### 0x88 - Division (double)
Dived two doubles and push result to stack
`PUSH SI / DI`

Input:
SI - pointer to first double
DI - pointer to second double

### 0x89 - Division tmpVarFloat by float DI
divide tmpVarFloat by float storing result in tmpVarFloat

Input:

    DI - float - pointer to float to divide by

### 0x8A - Division tmpVarDouble by double DI
divide tmpVarDouble by double storing result in tmpVarDouble

Input:

    DI - double - pointer to double to divide by

### 0x8B - Division float SI by tmpVarFloat
divide float by tmpVarFloat storing result in tmpVarFloat

Input:

    SI - float - pointer to float to divide

### 0x8C - Division double SI by tmpVarDouble
divide double by tmpVarDouble storing result in tmpVarDouble

Input:

    SI - double - pointer to double to divide

### 0x8f - Multiplication (float)
Multiply two floats together and push result to stack
`PUSH SI * DI`

Input:
SI - pointer to first float
DI - pointer to second float

### 0x90 - Multiplication (double)
Multiply two doubles together and push result to stack
`PUSH SI * DI`

Input:
SI - pointer to first double
DI - pointer to second double

### 0x91 - Multiplication float tmpVarFloat DI
Multiply a float value in DI by tmpVarFloat and store result in tmpVarFloat

Input:
    
    DI - float - pointer to float

### 0x92 - Multiplication double tmpVarDouble DI
Multiply a float value in DI by tmpVarDouble and store result in tmpVarDouble

Input:

    DI - double - pointer to double

### 0x93 - Multiplication float tmpVarFloat SI
Multiply a float value in SI by tmpVarFloat and store result in tmpVarFloat

Input:

    SI - float - pointer to float

### 0x94 - Multiplication double tmpVarDouble SI
Multiply a float value in SI by tmpVarDouble and store result in tmpVarDouble

Input:

    SI - double - pointer to double

### 0x95 - Multiplication stack * temp var (float) (3 param)
Has second byte seems to start at 0x80 and increment for each call to op
Result of multiplication is stored in temp var

### 0x96 - Multiplication stack * temp var (double) (3 param)
Has second byte seems to start at 0x80 and increment for each call to op
Result of multiplication is stored in temp var

### 0x97 - Subtraction (float)
subtract two floats and push result to stack
`PUSH SI - DI`

Input:
SI - pointer to first float
DI - pointer to second float

### 0x98 - Subtraction (double)
subtract two doubles and push result to stack
`PUSH SI - DI`

Input:
SI - pointer to first double
DI - pointer to second double

### 0x99 - Subtraction temp var - (float)
Subtract float from temp var storing result in temp var

Input:

    DI - float - pointer to float to subtract.

### 0x9A - Subtraction temp var - (double)
Subtract double from temp var storing result in temp var

Input:

    DI - double - pointer to double to subtract.

### 0x9B - Subtraction (float) - temp var
Subtract temp var from float storing result in temp var

Input:

    SI - float - pointer to float to subtracted from.

### 0x9C - Subtraction (double) - temp var
Subtract temp var from double storing result in temp var

Input:

    SI - double - pointer to double to subtract from.

### 0x9D - Subtract tmpVarFloat from floatStackValue (3 param)
Has second byte operand which starts at 0x80 and increments.

### 0x9E - Subtract tmpVarFloat from doubleStackValue (3 param)
Has second byte operand which starts at 0x80 and increments.
`tmpVarDouble = doubleStackVal - tmpVarFloat`

### 0x9F - compare floats
Compare two floats and set x86 flags accordingly
eg.
```asm
       1000:0063 8b  f3           MOV        SI ,BX
       1000:0065 bf  62  18       MOV        DI ,0x1862
       1000:0068 cd  3f           INT        0x3f
       1000:006a 9f               ??         9Fh
       1000:006b 75  dd           JNZ        LAB_1000_004a
```

Input:

SI - left hand float pointer
DI - right hand float pointer

### 0xA0 - compare doubles
Compare two doubles and set x86 flags accordingly

Input:

SI - left hand double pointer
DI - right hand double pointer

### 0xA1 - compare float to temp var
Compare float to temp var

Input:

    DI - float - pointer to float to compare with temp var

### 0xA2 - compare double to temp var
Compare double to temp var

Input:

    DI - double - pointer to double to compare with temp var
### 0xA5 - Compare tmpVarFloat and stack float value

```basic
IF c% = POINT(1) THEN
```

```asm
       1000:008d 8b  1e  62       MOV        BX ,word ptr [0x1862 ]
                 18
       1000:0091 cd  3f           INT        0x3f
       1000:0093 57              db         57h                       I3F_57_STORE_INT_AS_FLOAT_TMP
       1000:0094 bb  01  00       MOV        BX ,0x1
       1000:0097 ba  ff  7f       MOV        DX ,0x7fff
       1000:009a cd  3f           INT        0x3f
       1000:009c 71              db         71h                       I3F_71_UNK
       1000:009d 80              ??         80h
       1000:009e cd  3d           INT        0x3d
       1000:00a0 2a              db         2Ah                       INT_3D_2A_POINT_VAL
       1000:00a1 cd  3f           INT        0x3f
       1000:00a3 a5              db         A5h                       I3F_A5_UNK
       1000:00a4 80              ??         80h
       1000:00a5 74  03           JZ         LAB_1000_00aa
       1000:00a7 e9  0c  00       JMP        LAB_1000_00b6
```

### 0xA7 - compare float with zero
Compare float variable with zero and set zero flag accordingly

```asm
       1000:004c be  56  18       MOV        SI ,0x1856               FLOAT VALUE
       1000:004f cd  3f           INT        0x3f
       1000:0051 a7              db         A7h                       I3F_A7_COMPARE_FLOAT_ZERO
       1000:0052 74  03           JZ         LAB_1000_0057
       1000:0054 e9  0c  00       JMP        LAB_1000_0063
```

Input:

    SI - float - pointer to float

### 0xA8 - compare double with zero
Compare double variable with zero and set zero flag accordingly

Input:

    SI - double - pointer to double

### 0xA9 - compare tmpVarFloat with zero
Compare tmpFloatValue with zero and set flags accordingly

### 0xAA - compare tmpVarDouble with zero
Compare tmpDoubleValue with zero and set flags accordingly

### 0xAB - multiply float by power of 2
Multiply float by power of 2 (2 byte command) push resulting float to stack

eg. multiply float at 0x185a by 8.
```asm
       1000:0087 8b  f2           MOV        SI ,0x185a
       1000:0089 cd  3f           INT        0x3f
       1000:008b ab              db         ABh
       1000:008c 04              ??         03h
```

Input:

    SI - pointer to float to multiply
    Second command byte - number of power to multiply by. eg 3 for 2^3 multiply by 8

### 0xAC - multiply double by power of 2
Multiply double by power of 2 (2 byte command) push resulting double to stack

Input:

    SI - pointer to double to multiply
    Second command byte - number of power to multiply by. eg 3 for 2^3 multiply by 8

### 0xAD - multiply tmpVarFloat by power of 2
`tmpVarFloat = tempVarFloat * 2^n`
n is supplied in command operand

eg. `TIMER * 16`

```asm
       1000:00a4 cd  3d           INT        0x3d
       1000:00a6 43              db         43h                   INT_3D_43_TIMER
       1000:00a7 cd  3f           INT        0x3f
       1000:00a9 ad              db         ADh                   I3F_AD_MUL_TMP_VAR_POWER_OF_2_FLOAT
       1000:00aa 04              ??         04h
```

### 0xAE - multiply tmpVarDouble by power of 2
`tmpVarDouble = tempVarDouble * 2^n`
n is supplied in command operand

### 0xAF - float negation
Store negation of float in temp var

Input:

    SI - float - pointer to float to negate.

### 0xB0 - double negation
Store negation of double in temp var

Input:

    SI - double - pointer to double to negate.

### 0xB3 - ?? FIELD start maybe

Input:

    BX - filenum - integer

### 0xB4 - FIELD var
Allocates space for variables in a random-access file buffer.

Input:

    BX - pointer to field string 
    DX - fieldWidth - integer

### 0xB5 - INPUT from keyboard
read input from file or device (2 byte command)
`INPUT[;]["prompt" {; | ,}] variable [,variable]...`

Input:

    BX - pointer to prompt string
    second byte - unknown. *TODO*

### 0xB6 - INPUT file/device
Read input data from file/device

Input:

    BX - filenum

### 0xB7 - INPUT arguments
Seems to setup number and type of arguments
Variable length command bytes

Input: 

    first extra byte - number of arguments
    variable number of additional bytes - type of argument. 4 = string 2 = float

### 0xB8 - INPUT load variable value
Loads the parsed value into variable

Input:

    BX - pointer to target variable

### 0xBA - LEN
Length of string
`l = LEN(s$)`

Input:

    BX - string - pointer to string

Return:

    BX - length - integer value

### 0xBC - print to screen start
Seems to be set when printing data to screen.

eg.
```asm
       1000:009e cd  3f           INT        0x3f
       1000:00a0 bc              db         BCh           I3F_BC_PRINT_TO_SCREEN_START
       1000:00a1 8b  da           MOV        BX ,DX
       1000:00a3 cd  3f           INT        0x3f
       1000:00a5 6e              db         6Eh           I3F_6E_UNK
       1000:00a6 cd  3e           INT        0x3e
       1000:00a8 79              db         79h           INT_3E_79_PRINT
```

### 0xBD - PRINT USING
Formatted Screen Display

`PRINT USING strexpr; exprlist [;]`

Print params are seperate opcodes same as PRINT

Input:

    BX - strexpr - pointer to formatting string

### 0xBE - PRINT \#
Print to file

`PRINT #1, "hello"`

Input:

    BX - filehandle - integer value

### 0xBB - ASC
Returns the ASCII value of the first character of a string expression.
string passed in BX
ASCII val returned in BX
