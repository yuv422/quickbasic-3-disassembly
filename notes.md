# QuickBasic 3 disassembly & reverse engineering notes

<!-- TOC -->
* [QuickBasic 3 disassembly & reverse engineering notes](#quickbasic-3-disassembly--reverse-engineering-notes)
  * [BRUN30.EXE Runtime](#brun30exe-runtime)
  * [DEF FN](#def-fn)
  * [GOSUB](#gosub)
  * [GOTO](#goto)
  * [INP](#inp)
  * [Temp variables](#temp-variables)
    * [Numeric temp slots](#numeric-temp-slots)
  * [BASIC Compiled interrupt functions](#basic-compiled-interrupt-functions)
    * [Dispatch tables](#dispatch-tables)
    * [INT 3 (0xCC) event checks](#int-3-0xcc-event-checks)
    * [Debug builds (/D)](#debug-builds-d)
  * [BSAVE format](#bsave-format)
  * [0x3d Interrupt](#0x3d-interrupt)
    * [0x0 - far call stub](#0x0---far-call-stub)
    * [0x1 - FIX (float)](#0x1---fix-float)
    * [0x2 - FIX (double)](#0x2---fix-double)
    * [0x3 - INT (float)](#0x3---int-float)
    * [0x4 - INT (double)](#0x4---int-double)
    * [0x5 - CHR$](#0x5---chr)
    * [0x6 - INKEY$](#0x6---inkey)
    * [0x7 - INPUT$](#0x7---input)
    * [0x8 - INSTR (start position)](#0x8---instr-start-position)
    * [0x9 - INSTR](#0x9---instr)
    * [0xA - MID$](#0xa---mid)
    * [0xB - LEFT$](#0xb---left)
    * [0xC - RIGHT$](#0xc---right)
    * [0xD - SPACE$](#0xd---space)
    * [0xE - STRING$ (m.n)](#0xe---string-mn)
    * [0xF - STRING$ (m,string)](#0xf---string-mstring)
    * [0x10 - STR$ (integer)](#0x10---str-integer)
    * [0x11 - STR$](#0x11---str)
    * [0x12 - STR$ (double)](#0x12---str-double)
    * [0x13 - VAL](#0x13---val)
    * [0x14 - HEX$ (integer)](#0x14---hex-integer)
    * [0x15 - HEX$ (float)](#0x15---hex-float)
    * [0x16 - OCT$ (integer)](#0x16---oct-integer)
    * [0x17 - OCT$ (float)](#0x17---oct-float)
    * [0x18 - CVI](#0x18---cvi)
    * [0x19 - CVS](#0x19---cvs)
    * [0x1A - CVD](#0x1a---cvd)
    * [0x1B - MKI$](#0x1b---mki)
    * [0x1C - MKS$](#0x1c---mks)
    * [0x1D - MKD$](#0x1d---mkd)
    * [0x1E - ERL](#0x1e---erl)
    * [0x1F - ERR](#0x1f---err)
    * [0x20 - LPOS](#0x20---lpos)
    * [0x21 - POS](#0x21---pos)
    * [0x22 - INT (integer)](#0x22---int-integer)
    * [0x23 - DATE$](#0x23---date)
    * [0x24 - TIME$](#0x24---time)
    * [0x25 - CSRLIN](#0x25---csrlin)
    * [0x26 - PEN](#0x26---pen)
    * [0x27 - POINT (x, y)](#0x27---point-x-y)
    * [0x28 - POINT (x, y) Float](#0x28---point-x-y-float)
    * [0x29 - POINT (x, y) integer x, float y](#0x29---point-x-y-integer-x-float-y)
    * [0x2A - POINT value](#0x2a---point-value)
    * [0x2B - PMAP](#0x2b---pmap)
    * [0x2C - SCREEN (function)](#0x2c---screen-function)
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
    * [0x44 - PLAY (function)](#0x44---play-function)
    * [0x45 - IOCTL$](#0x45---ioctl)
    * [0x46 - ENVIRON$ (name)](#0x46---environ-name)
    * [0x47 - ENVIRON$ (ordinal)](#0x47---environ-ordinal)
    * [0x48 - ERDEV](#0x48---erdev)
    * [0x49 - ERDEV$](#0x49---erdev)
    * [0x4A - COMMAND$](#0x4a---command)
    * [0x4B - 0x61 - unused](#0x4b---0x61---unused)
    * [0x62 - PEEK](#0x62---peek)
    * [0x63 - FRE (string)](#0x63---fre-string)
    * [0x64 - FRE (num)](#0x64---fre-num)
    * [0x65 - SADD](#0x65---sadd)
    * [0x66 - 0x68 - unused](#0x66---0x68---unused)
  * [0x3e Interrupt](#0x3e-interrupt)
    * [0x1 - END](#0x1---end)
    * [0x2 - (END PROGRAM)](#0x2---end-program)
    * [0x3 - STOP](#0x3---stop)
    * [0x4 - WIDTH (screen)](#0x4---width-screen)
    * [0x5 - WIDTH LPRINT](#0x5---width-lprint)
    * [0x6 - WRITE start](#0x6---write-start)
    * [0x7 - WRITE to device start](#0x7---write-to-device-start)
    * [0x8 - RANDOMIZE (no args)](#0x8---randomize-no-args)
    * [0x9 - RANDOMIZE](#0x9---randomize)
    * [0xA - set USING format string](#0xa---set-using-format-string)
    * [0xB - CLEAR](#0xb---clear)
    * [0xC - CLEAR (no stack args)](#0xc---clear-no-stack-args)
    * [0xD - RUN (file)](#0xd---run-file)
    * [0xE - CHAIN](#0xe---chain)
    * [0xF - TRON](#0xf---tron)
    * [0x10 - TROFF](#0x10---troff)
    * [0x11 - ERROR](#0x11---error)
    * [0x12 - RESUME NEXT](#0x12---resume-next)
    * [0x13 - RESUME](#0x13---resume)
    * [0x14 - DEF SEG (default)](#0x14---def-seg-default)
    * [0x15 - DEF SEG](#0x15---def-seg)
    * [0x16 - RESET](#0x16---reset)
    * [0x17 - DATE$ (write)](#0x17---date-write)
    * [0x18 - TIME$ (write)](#0x18---time-write)
    * [0x19 - BLOAD (offset from file)](#0x19---bload-offset-from-file)
    * [0x1A - BLOAD](#0x1a---bload)
    * [0x1B - BSAVE](#0x1b---bsave)
    * [0x1C - FILES](#0x1c---files)
    * [0x1D - FILES (no argument)](#0x1d---files-no-argument)
    * [0x1E - OPEN](#0x1e---open)
    * [0x1F - OPEN mode (string)](#0x1f---open-mode-string)
    * [0x20 - OPEN mode](#0x20---open-mode)
    * [0x21 - CLOSE](#0x21---close)
    * [0x22 - CLOSE (close all open files)](#0x22---close-close-all-open-files)
    * [0x23 - NAME](#0x23---name)
    * [0x24 - KILL](#0x24---kill)
    * [0x25 - GET (default)](#0x25---get-default)
    * [0x26 - GET](#0x26---get)
    * [0x27 - PUT (File IO default)](#0x27---put-file-io-default)
    * [0x28 - PUT (File IO)](#0x28---put-file-io)
    * [0x29 - WIDTH # (file)](#0x29---width--file)
    * [0x2A - WIDTH (device)](#0x2a---width-device)
    * [0x2B - BEEP](#0x2b---beep)
    * [0x2C - 0x2E - unused](#0x2c---0x2e---unused)
    * [0x2F - CIRCLE (start angle)](#0x2f---circle-start-angle)
    * [0x30 - CIRCLE (end angle)](#0x30---circle-end-angle)
    * [0x31 - CIRCLE (aspect ratio)](#0x31---circle-aspect-ratio)
    * [0x32 - CLS ](#0x32---cls-)
    * [0x33 - Add argument to COLOR command](#0x33---add-argument-to-color-command)
    * [0x34 - COLOR arg not supplied](#0x34---color-arg-not-supplied)
    * [0x35 - COLOR](#0x35---color)
    * [0x36 - DRAW](#0x36---draw)
    * [0x37 - event trapping init](#0x37---event-trapping-init)
    * [0x38 - 0x39 - unused](#0x38---0x39---unused)
    * [0x3A - GET (gfx)](#0x3a---get-gfx)
    * [0x3B - STEP](#0x3b---step)
    * [0x3C - KEY on/off/list](#0x3c---key-onofflist)
    * [0x3D - KEY](#0x3d---key)
    * [0x3E - LCOPY](#0x3e---lcopy)
    * [0x3F - 0x41 - unused](#0x3f---0x41---unused)
    * [0x42 - LOCATE arg](#0x42---locate-arg)
    * [0x43 - LOCATE arg not supplied](#0x43---locate-arg-not-supplied)
    * [0x44 - LOCATE](#0x44---locate)
    * [0x45 - device unavailable stub](#0x45---device-unavailable-stub)
    * [0x46 - MOTOR](#0x46---motor)
    * [0x47 - unused](#0x47---unused)
    * [0x48 - PAINT (color)](#0x48---paint-color)
    * [0x49 - PAINT (tile)](#0x49---paint-tile)
    * [0x4A - PALETTE](#0x4a---palette)
    * [0x4B - PALETTE USING](#0x4b---palette-using)
    * [0x4C - PEN ON](#0x4c---pen-on)
    * [0x4D - PEN OFF](#0x4d---pen-off)
    * [0x4E - PEN STOP](#0x4e---pen-stop)
    * [0x4F - 0x50 - unused](#0x4f---0x50---unused)
    * [0x51 - PLAY](#0x51---play)
    * [0x52 - PLAY ON](#0x52---play-on)
    * [0x53 - PLAY OFF](#0x53---play-off)
    * [0x54 - PLAY STOP](#0x54---play-stop)
    * [0x55 - PRESET](#0x55---preset)
    * [0x56 - PSET](#0x56---pset)
    * [0x57 - unused](#0x57---unused)
    * [0x58 - PUT (graphics)](#0x58---put-graphics)
    * [0x59 - SCREEN arg](#0x59---screen-arg)
    * [0x5A - SCREEN arg not supplied](#0x5a---screen-arg-not-supplied)
    * [0x5B - SCREEN](#0x5b---screen)
    * [0x5C - STRIG ON](#0x5c---strig-on)
    * [0x5D - STRIG OFF](#0x5d---strig-off)
    * [0x5E - SOUND](#0x5e---sound)
    * [0x5F - SOUND (play)](#0x5f---sound-play)
    * [0x60 - 0x61 - unused](#0x60---0x61---unused)
    * [0x62 - PCOPY](#0x62---pcopy)
    * [0x63 - unused](#0x63---unused)
    * [0x64 - COM(n) ON](#0x64---comn-on)
    * [0x65 - COM(n) OFF](#0x65---comn-off)
    * [0x66 - COM(n) STOP](#0x66---comn-stop)
    * [0x67 - KEY(n) ON](#0x67---keyn-on)
    * [0x68 - KEY(n) OFF](#0x68---keyn-off)
    * [0x69 - KEY(n) STOP](#0x69---keyn-stop)
    * [0x6A - STRIG(n) ON](#0x6a---strign-on)
    * [0x6B - STRIG(n) OFF](#0x6b---strign-off)
    * [0x6C - STRIG(n) STOP](#0x6c---strign-stop)
    * [0x6D - LOCK](#0x6d---lock)
    * [0x6E - UNLOCK](#0x6e---unlock)
    * [0x6F - WINDOW (first corner)](#0x6f---window-first-corner)
    * [0x70 - WINDOW (second corner)](#0x70---window-second-corner)
    * [0x71 - WINDOW (no arguments)](#0x71---window-no-arguments)
    * [0x72 - VIEW (first corner)](#0x72---view-first-corner)
    * [0x73 - VIEW (second corner)](#0x73---view-second-corner)
    * [0x74 - VIEW](#0x74---view)
    * [0x75 - VIEW (no arguments)](#0x75---view-no-arguments)
    * [0x76 - TIMER ON](#0x76---timer-on)
    * [0x77 - TIMER OFF](#0x77---timer-off)
    * [0x78 - TIMER STOP](#0x78---timer-stop)
    * [0x79 - PRINT](#0x79---print)
    * [0x7A - OPEN ACCESS / LOCK clause](#0x7a---open-access--lock-clause)
    * [0x7B - LOCK/UNLOCK record number (long)](#0x7b---lockunlock-record-number-long)
    * [0x7C - SHELL](#0x7c---shell)
    * [0x7D - IOCTL](#0x7d---ioctl)
    * [0x7E - ENVIRON](#0x7e---environ)
    * [0x7F - CHDIR](#0x7f---chdir)
    * [0x80 - MKDIR](#0x80---mkdir)
    * [0x81 - RMDIR](#0x81---rmdir)
    * [0x82 - install break key handler](#0x82---install-break-key-handler)
    * [0x83 - save stack pointer before CALL](#0x83---save-stack-pointer-before-call)
    * [0x84 - LINE (start position)](#0x84---line-start-position)
    * [0x85 - LINE (end position)](#0x85---line-end-position)
    * [0x86 - LINE](#0x86---line)
    * [0x87 - GET (start position)](#0x87---get-start-position)
    * [0x88 - GET (end position)](#0x88---get-end-position)
    * [0x89 - PUT (position)](#0x89---put-position)
    * [0x8A - PRESET](#0x8a---preset)
    * [0x8B - PSET (point already set)](#0x8b---pset-point-already-set)
    * [0x8C - CIRCLE](#0x8c---circle)
    * [0x8D - set point (x, y)](#0x8d---set-point-x-y)
    * [0x8E - 0xA0 - unused](#0x8e---0xa0---unused)
    * [0xA1 - VIEW PRINT](#0xa1---view-print)
    * [0xA2 - 0xA3 - unused](#0xa2---0xa3---unused)
    * [0xA4 - COM(n) STOP (duplicate)](#0xa4---comn-stop-duplicate)
    * [0xA5 - POKE](#0xa5---poke)
  * [0x3f Interrupt](#0x3f-interrupt)
    * [0x0 - POKE (table overlap)](#0x0---poke-table-overlap)
    * [0x1 - array element offset (static array, bounds checked)](#0x1---array-element-offset-static-array-bounds-checked)
    * [0x2 - ON ERROR trap](#0x2---on-error-trap)
    * [0x3 - ON COM trap](#0x3---on-com-trap)
    * [0x4 - ON KEY trap](#0x4---on-key-trap)
    * [0x5 - ON PEN trap](#0x5---on-pen-trap)
    * [0x6 - ON STRIG](#0x6---on-strig)
    * [0x7 - ON TIMER](#0x7---on-timer)
    * [0x8 - ON PLAY trap](#0x8---on-play-trap)
    * [0x9 - RESUME label](#0x9---resume-label)
    * [0xA - RSET](#0xa---rset)
    * [0xB - unused](#0xb---unused)
    * [0xC - byte range check](#0xc---byte-range-check)
    * [0xD - READ (float)](#0xd---read-float)
    * [0xE - READ (double)](#0xe---read-double)
    * [0xF - READ (integer)](#0xf---read-integer)
    * [0x10 - READ (string)](#0x10---read-string)
    * [0x11 - SWAP (float)](#0x11---swap-float)
    * [0x12 - SWAP (double)](#0x12---swap-double)
    * [0x13 - SWAP (integer)](#0x13---swap-integer)
    * [0x14 - SWAP (string)](#0x14---swap-string)
    * [0x15 - VARPTR$ float](#0x15---varptr-float)
    * [0x16 - VARPTR$ double](#0x16---varptr-double)
    * [0x17 - VARPTR$ integer](#0x17---varptr-integer)
    * [0x18 - VARPTR$ string](#0x18---varptr-string)
    * [0x19 - float to int](#0x19---float-to-int)
    * [0x1A - double to int](#0x1a---double-to-int)
    * [0x1B - tmpVarFloat to int](#0x1b---tmpvarfloat-to-int)
    * [0x1C - tmpVarDouble to int](#0x1c---tmpvardouble-to-int)
    * [0x1D - float to boolean](#0x1d---float-to-boolean)
    * [0x1E - double to boolean](#0x1e---double-to-boolean)
    * [0x1F - tmpVarFloat to boolean](#0x1f---tmpvarfloat-to-boolean)
    * [0x20 - tmpVarDouble to boolean](#0x20---tmpvardouble-to-boolean)
    * [0x21 - float to unsigned int](#0x21---float-to-unsigned-int)
    * [0x22 - tmpVarFloat to unsigned int](#0x22---tmpvarfloat-to-unsigned-int)
    * [0x23 - Exponentiation Operator (float)](#0x23---exponentiation-operator-float)
    * [0x24 - Exponentiation Operator (double)](#0x24---exponentiation-operator-double)
    * [0x25 - Exponentiation Operator using tempFloatVar (float)](#0x25---exponentiation-operator-using-tempfloatvar-float)
    * [0x26 - Exponentiation Operator using tempDoubleVar (double)](#0x26---exponentiation-operator-using-tempdoublevar-double)
    * [0x27 - Exponentiation Operator float ^ tempFloatVar](#0x27---exponentiation-operator-float--tempfloatvar)
    * [0x28 - Exponentiation Operator double ^ tempDoubleVar](#0x28---exponentiation-operator-double--tempdoublevar)
    * [0x29 - Exponentiation Operator stack ^ tempFloatVar (3 param)](#0x29---exponentiation-operator-stack--tempfloatvar-3-param)
    * [0x2A - Exponentiation Operator stack ^ tempDoubleVar (3 param)](#0x2a---exponentiation-operator-stack--tempdoublevar-3-param)
    * [0x2B - ABS (float)](#0x2b---abs-float)
    * [0x2C - ABS (double)](#0x2c---abs-double)
    * [0x2D - ABS (float) temp var](#0x2d---abs-float-temp-var)
    * [0x2E - ABS (double) temp var](#0x2e---abs-double-temp-var)
    * [0x2F - SGN (float)](#0x2f---sgn-float)
    * [0x30 - SGN (double)](#0x30---sgn-double)
    * [0x31 - SGN (float) temp var](#0x31---sgn-float-temp-var)
    * [0x32 - SGN (double) temp var](#0x32---sgn-double-temp-var)
    * [0x33 - RESTORE](#0x33---restore)
    * [0x34 - RESTORE line](#0x34---restore-line)
    * [0x35 - SPC](#0x35---spc)
    * [0x36 - SPC (byte)](#0x36---spc-byte)
    * [0x37 - TAB](#0x37---tab)
    * [0x38 - TAB (byte)](#0x38---tab-byte)
    * [0x39 - start function](#0x39---start-function)
    * [0x3A - end function](#0x3a---end-function)
    * [0x3B - copy string to temp](#0x3b---copy-string-to-temp)
    * [Dynamic array element opcodes](#dynamic-array-element-opcodes)
    * [0x3C - load dynamic array element (bounds checked)](#0x3c---load-dynamic-array-element-bounds-checked)
    * [0x3D - store dynamic array element (bounds checked)](#0x3d---store-dynamic-array-element-bounds-checked)
    * [0x3E - set dynamic array element target (bounds checked)](#0x3e---set-dynamic-array-element-target-bounds-checked)
    * [0x3F - SWAP dynamic array elements (bounds checked)](#0x3f---swap-dynamic-array-elements-bounds-checked)
    * [0x40 - SWAP dynamic array element with variable](#0x40---swap-dynamic-array-element-with-variable)
    * [0x41 - VARPTR dynamic array element (bounds checked)](#0x41---varptr-dynamic-array-element-bounds-checked)
    * [0x42 - array element offset (dynamic array, bounds checked)](#0x42---array-element-offset-dynamic-array-bounds-checked)
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
    * [0x53 - start subroutine](#0x53---start-subroutine)
    * [0x54 - end subroutine](#0x54---end-subroutine)
    * [0x55 - concatenate strings](#0x55---concatenate-strings)
    * [0x56 - store int as double in temp var](#0x56---store-int-as-double-in-temp-var)
    * [0x57 - store int as float in temp var](#0x57---store-int-as-float-in-temp-var)
    * [0x58 - GOSUB](#0x58---gosub)
    * [0x59 - line trace / break check](#0x59---line-trace--break-check)
    * [0x5A - LINE INPUT](#0x5a---line-input)
    * [0x5B - LSET](#0x5b---lset)
    * [0x5C - MID$ statement](#0x5c---mid-statement)
    * [0x5E - ON GOTO](#0x5e---on-goto)
    * [0x5D - ON GOSUB](#0x5d---on-gosub)
    * [0x5F - RETURN line](#0x5f---return-line)
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
    * [0x70 - PUSH double](#0x70---push-double)
    * [0x71 - Push float temp var onto stack (3 param)](#0x71---push-float-temp-var-onto-stack-3-param)
    * [0x72 - Push double temp var onto stack (3 param)](#0x72---push-double-temp-var-onto-stack-3-param)
    * [0x74 - convert float temp var to double temp var](#0x74---convert-float-temp-var-to-double-temp-var)
    * [0x73 - store float as double in temp var](#0x73---store-float-as-double-in-temp-var)
    * [0x75 - CINT (float)](#0x75---cint-float)
    * [0x76 - CINT (double)](#0x76---cint-double)
    * [0x77 - CINT (tmpVarFloat)](#0x77---cint-tmpvarfloat)
    * [0x78 - CINT (tmpVarDouble)](#0x78---cint-tmpvardouble)
    * [0x79 - CSNG](#0x79---csng)
    * [0x7A - convert temp var from double to float](#0x7a---convert-temp-var-from-double-to-float)
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
    * [0x8D - Division stack / temp var (float) (3 param)](#0x8d---division-stack--temp-var-float-3-param)
    * [0x8E - Division stack / temp var (double) (3 param)](#0x8e---division-stack--temp-var-double-3-param)
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
    * [0x9E - Subtract tmpVarDouble from doubleStackValue (3 param)](#0x9e---subtract-tmpvardouble-from-doublestackvalue-3-param)
    * [0x9F - compare floats](#0x9f---compare-floats)
    * [0xA0 - compare doubles](#0xa0---compare-doubles)
    * [0xA1 - compare float to temp var](#0xa1---compare-float-to-temp-var)
    * [0xA2 - compare double to temp var](#0xa2---compare-double-to-temp-var)
    * [0xA3 - compare float with temp var](#0xa3---compare-float-with-temp-var)
    * [0xA4 - compare double with temp var](#0xa4---compare-double-with-temp-var)
    * [0xA5 - Compare tmpVarFloat and stack float value](#0xa5---compare-tmpvarfloat-and-stack-float-value)
    * [0xA6 - Compare tmpVarDouble and stack double value](#0xa6---compare-tmpvardouble-and-stack-double-value)
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
    * [0xB1 - tmpVarFloat negation](#0xb1---tmpvarfloat-negation)
    * [0xB2 - tmpVarDouble negation](#0xb2---tmpvardouble-negation)
    * [0xB3 - FIELD start](#0xb3---field-start)
    * [0xB4 - FIELD var](#0xb4---field-var)
    * [0xB5 - INPUT from keyboard](#0xb5---input-from-keyboard)
    * [0xB6 - INPUT file/device](#0xb6---input-filedevice)
    * [0xB7 - INPUT arguments](#0xb7---input-arguments)
    * [0xB8 - INPUT load variable value](#0xb8---input-load-variable-value)
    * [0xB9 - INPUT load dynamic array element](#0xb9---input-load-dynamic-array-element)
    * [0xBA - LEN](#0xba---len)
    * [0xBC - print to screen start](#0xbc---print-to-screen-start)
    * [0xBD - PRINT USING](#0xbd---print-using)
    * [0xBE - PRINT \#](#0xbe---print-)
    * [0xBB - ASC](#0xbb---asc)
    * [0xBF - PRINT # USING](#0xbf---print--using)
    * [0xC0 - LPRINT](#0xc0---lprint)
    * [0xC1 - LPRINT USING](#0xc1---lprint-using)
    * [0xC2 - 0xC3 - unused](#0xc2---0xc3---unused)
    * [0xC4 - load dynamic array element](#0xc4---load-dynamic-array-element)
    * [0xC5 - store dynamic array element](#0xc5---store-dynamic-array-element)
    * [0xC6 - set dynamic array element target](#0xc6---set-dynamic-array-element-target)
    * [0xC7 - SWAP dynamic array elements](#0xc7---swap-dynamic-array-elements)
    * [0xC8 - SWAP dynamic array element with variable](#0xc8---swap-dynamic-array-element-with-variable)
    * [0xC9 - VARPTR dynamic array element](#0xc9---varptr-dynamic-array-element)
    * [0xCA - Load float from stack into temp var (2 param)](#0xca---load-float-from-stack-into-temp-var-2-param)
    * [0xCB - Load double from stack into temp var (2 param)](#0xcb---load-double-from-stack-into-temp-var-2-param)
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

The two overlap. A MBF double is 4 extra low mantissa bytes followed by the same 4 bytes as a
MBF float, so `DS:1A` is the top half of the double at `DS:16`. Converting the float temp var
to a double is done by zeroing `DS:16`-`DS:19`.

### Numeric temp slots
Opcodes marked "(3 param)" carry an extra byte after the opcode, e.g. `INT 0x3f / 0x71 / 0x80`.
This byte selects an 8 byte temporary slot used to hold intermediate results while evaluating
an expression. Slot address = `base + (byte & 0x7f) * 8`. The compiler numbers them from `0x80`.

eg. `y = a(2) + a(3) * a(4)`
```
load a(2) -> tmpVarFloat ; 0x71 0x80   slot0 = tmpVarFloat
load a(3) -> tmpVarFloat ; 0x71 0x81   slot1 = tmpVarFloat
load a(4) -> tmpVarFloat ; 0x95 0x81   tmpVarFloat = slot1 * tmpVarFloat
                           0x85 0x80   tmpVarFloat = slot0 + tmpVarFloat
                           0x7D        y = tmpVarFloat
```

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

### Dispatch tables
The handlers are found in jump tables in `BRUN30.EXE`, indexed directly by the opcode byte.

| Interrupt | Table             | Valid opcodes |
|-----------|-------------------|---------------|
| 0x3d      | `int_3d_func_ptrs` @ `1000:0171` | 0x00 - 0x68 |
| 0x3e      | `int_3e_func_ptrs` @ `1000:0243` | 0x00 - 0xA5 |
| 0x3f      | `int_3f_func_ptrs` @ `1000:038d` | 0x00 - 0xCB |

The tables are bigger than the Ghidra labels. 0x3d really has 105 entries (SADD is 0x65).
0x3f runs until the dispatcher code at `1000:0526`. The 0x3e table runs straight into the 0x3f
table, so 0x3e `0xA5` (POKE) and 0x3f `0x00` are the same word.

Unused slots point at `1000:09fa`, which raises error 73 "Advanced feature unavailable".

The runtime's error stubs are a chain of `MOV BL, errnum` instructions. Handlers jump into them on bad input:

| Address | Error |
|---------|-------|
| `1000:099d` | 5 Illegal function call |
| `1000:09ca` | 52 Bad file number |
| `1000:09d0` | 54 Bad file mode |
| `1000:0a18` | 5 Illegal function call |
| `1000:0a1e` | 7 Out of memory |
| `1000:0a21` | 9 Subscript out of range |
| `1000:0a2a` | 20 RESUME without error |
| `1000:0a39` | 68 Device unavailable |
| `1000:0a3c` | 73 Advanced feature unavailable |

### INT 3 (0xCC) event checks
When compiled with event trapping (`/V` or `/W`), the compiler emits a single `0xCC` (`INT 3`) byte
after statements. The runtime hooks INT 3 (see 0x3e `0x37`) and uses it to poll for pending
events (ON KEY/TIMER/PLAY/STRIG/COM/PEN). This is the "unknown second byte" seen after some opcodes.

```asm
INT 0x3f
db  0x07    ; ON TIMER
INT 3       ; event check
INT 0x3e
db  0x76    ; TIMER ON
INT 3       ; event check
```

### Debug builds (/D)
With `/D` every statement starts with 0x3f `0x59` (line trace / break check). GOSUB and RETURN become
0x3f `0x58` and 0x3f `0x60` (this also happens in `/V` and `/W` builds). Array accesses use the bounds checking opcodes 0x3f `0x01`, `0x3C`-`0x42`.

## BSAVE format
Basic can save and load chunks of memory from files. The format of the save file is as follows

It uses little endian format.

```
00 byte - `0xFD` magic value
01 word - memory segment (the DEF SEG value)
03 word - memory offset
05 word - length of data in bytes
07 data
...
byte - `0x1A` end of file marker byte  
```

## 0x3d Interrupt

### 0x0 - far call stub
Special case in the dispatcher. Followed by a 2 byte operand which is an offset into a table of
far pointers (the table's segment is stored at `[0xa1e]`). The runtime patches the 5 bytes
`CD 3D 00 lo hi` into a `CALL FAR seg:off` (`0x9A`) to the target, then jumps there.
Later executions call the routine directly. Looks to be used to reach routines outside the
interrupt tables.

```asm
INT 0x3d
db  0x00
dw  nnnn     ; offset of far pointer in table
```

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

### 0x8 - INSTR (start position)
`INSTR(n,stringexp1,stringexp2)`

Returns the character position within a string at which a substring is
found, starting the search at position n. n < 1 raises Illegal function call.

eg. `b = INSTR(7, src$, match$)`

Input:

    BX - n - integer value. 1 based start position
    DX - stringexp1 - string to search
    CX - stringexp2 - substring to match

Return:

    BX - integer value of offset. 1 based. 0 = no match

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

Return:

    BX - pointer to output string

### 0xB - LEFT$
Substring at Left. Left most n chars.
`s$ = LEFT$(stringexpr,n)`

Input:

    BX - stringexpr - pointer to string
    DX - n - integer value

Return:

    BX - pointer to output string

### 0xC - RIGHT$
Substring at Right. Right most n chars.
`s$ = RIGHT$(stringexpr,n)`

Input:

    BX - stringexpr - pointer to string
    DX - n - integer value

Return:

    BX - pointer to output string

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

### 0x10 - STR$ (integer)
String Representation of Numeric Expression

eg. `s$ = STR$(1%)`

Input:

    BX - integer value

Return:

    BX - pointer to string

### 0x11 - STR$
String Representation of Numeric Expression

Input:

    BX - float - pointer to float

Return:

    BX - pointer to string

### 0x12 - STR$ (double)
String Representation of Numeric Expression

eg. `s$ = STR$(d#)`

Input:

    BX - double - pointer to double

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

### 0x16 - OCT$ (integer)
Octal Value, as String. `s$ = OCT$(numexpr)`

Input:

    BX - integer value

Returns:

    BX - pointer to octal string

### 0x17 - OCT$ (float)
Octal Value, as String. `s$ = OCT$(numexpr)`

The float is converted to a 16 bit value first (same as 0x3f `0x21`).

Input:

    BX - pointer to float

Returns:

    BX - pointer to octal string

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

### 0x21 - POS
Current Cursor Column Position
`y = POS(n)`
n - dummy value. Can be any numeric integer value

Input:

    BX - n - integer value

Return:

    BX - integer value

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

### 0x26 - PEN
Light Pen Status
`y = PEN(n)`

Input:

    BX - n - integer value (0 - 9). Values above 9 raise Illegal function call.
        0   -1 if pen was down since last poll, otherwise 0
        1   x coordinate where pen was last pressed
        2   y coordinate where pen was last pressed
        3   current pen switch value. -1 if down, 0 if up
        4   last known valid x coordinate
        5   last known valid y coordinate
        6   character row where pen was last pressed
        7   character column where pen was last pressed
        8   last known character row
        9   last known character column

Return:

    BX - integer value

### 0x27 - POINT (x, y)
Get Attribute for point on screen

Input:

    BX - x - integer value
    DX - y - integer value

Return:

    BX - attribute - integer value

### 0x28 - POINT (x, y) Float
Get Attribute for point on screen

Input:

    BX - x - float value
    DX - y - float value

Return:

    BX - attribute - integer value

### 0x29 - POINT (x, y) integer x, float y
Get Attribute for point on screen. Mixed argument types.

eg. `y = POINT(1, 2.5)`

Input:

    BX - x - integer value
    DX - y - pointer to float value

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

### 0x2B - PMAP
Map Physical Coordinates to World. Result stored in tmpVarFloat.
`x = PMAP(expr, n)`

Input:

    BX - expr - pointer to float
    DX - n - integer value (0 - 3)
        0   world x to physical x
        1   world y to physical y
        2   physical x to world x
        3   physical y to world y

### 0x2C - SCREEN (function)
Character or attribute at specified screen location.
`c = SCREEN(row, col [,colorflag])`

Input:

    BX - row - integer value
    DX - col - integer value
    CX - colorflag - integer value. 0 returns the ASCII code, non zero returns the attribute

Return:

    BX - integer value

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

### 0x44 - PLAY (function)
Number of notes in the background music queue.
`notesLeft = PLAY(n)`

Input:

    BX - n - dummy integer value

Return:

    BX - number of notes - integer value

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

### 0x4B - 0x61 - unused
These all point to the "Advanced feature unavailable" stub (error 73).

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
Returns the address of a string expression.
`SADD(strexpr)`

Input:

    BX - strexpr - pointer to string

Return:

    BX - address of the string data - integer value. 0 for an empty string.

### 0x66 - 0x68 - unused
Point to the "Advanced feature unavailable" stub (error 73). 0x68 is the last entry in the table.

----
0x3e Interrupt
----
Seems to be used for commands.

### 0x1 - END
Terminate Program

### 0x2 - (END PROGRAM)
Found at the end of the program. Clean up and exit to DOS

### 0x3 - STOP
Halt program. Prints "STOP" (plus " in " and the line number when available) and terminates
like END.

### 0x4 - WIDTH (screen)
Set screen width and height
`WIDTH columns [,lines]`

eg. `WIDTH 80, 25`

Input:

    BX - columns - integer value
    DX - lines - integer value. 0xffff when not supplied

### 0x5 - WIDTH LPRINT
Set printer line width
`WIDTH LPRINT width`

Input:

    BX - width - integer value

### 0x6 - WRITE start
Start writing to screen. Items are then output with the PRINT item opcodes (0x3f `0x63`-`0x6E`),
quoted and comma separated, followed by 0x3e `0x79`.

eg. `WRITE a, s$`

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

### 0xA - set USING format string
Internal. Copies the format string for PRINT USING into the runtime and switches the
print item opcodes to formatted output. Reached through 0x3f `0xBD`, `0xBF` and `0xC1`.
Not seen emitted directly by the compiler.

Input:

    BX - pointer to format string

### 0xB - CLEAR
Close Files, Reset Variables, Set Stack Space

eg. `CLEAR , 512, 768`

Input:

    BX - first stack argument - integer value
    DX - second stack argument - integer value

### 0xC - CLEAR (no stack args)
Close Files, Reset Variables, Set Stack Space

`RUN` without a filename is compiled as this opcode followed by a `JMP` to the start of the program.

### 0xD - RUN (file)
Close files and run another program.
`RUN "filespec"`

Input:

    BX - filespec - pointer to string filename (.EXE is added if no extension is given)

### 0xE - CHAIN
Chain to another program

Input:

    BX - filespec - pointer to string filename (.EXE extension can be omitted)

### 0xF - TRON
Trace on. While enabled, the 0x3f `0x59` opcode prints `[linenumber]` for each statement.
Only emitted when compiled with `/D`. Otherwise TRON compiles to nothing.

### 0x10 - TROFF
Trace off. Only emitted when compiled with `/D`.

### 0x11 - ERROR
Force Error

Input:

    BX - errorCode - integer containing error code

### 0x12 - RESUME NEXT
Resume execution at the statement after the one that caused the error.
The runtime looks up the error address in the statement address table to find the next statement.
Raises error 20 (RESUME without error) when not in an error handler.

### 0x13 - RESUME
`RESUME` / `RESUME 0`. Resume execution at the statement that caused the error.
Raises error 20 (RESUME without error) when not in an error handler.

### 0x14 - DEF SEG (default)
returns the DEF SEG address to default value (`DS`).

### 0x15 - DEF SEG
Specifies the segment address from which arguments to BLOAD, BSAVE,
CALL ABSOLUTE, PEEK, and POKE will be offset.

Argument is passed on the stack. As a float.

### 0x16 - RESET
Close all disk files. Flushes the DOS buffers with INT 21h AH=0Dh (disk reset), then reselects
the current drive.

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

The mode is set before this opcode with 0x3e `0x20` (or 0x3e `0x1F` for the `OPEN "O", #n, "file"` form).
ACCESS and LOCK clauses are set with 0x3e `0x7A`. `AX` isn't used.

Input:

    BX - fileNum - integer
    DX - filename - pointer to string filename
    CX - length - integer. Record length from `LEN=`, 0 when not supplied

### 0x1F - OPEN mode (string)
Sets the file mode from a mode string for the old style OPEN syntax. Followed by 0x3e `0x1E`.
`OPEN "O", #2, "file"`

Only the first character is checked (case insensitive):
`I` = input, `O` = output, `R` = random, `A` = append.

Input:

    BX - mode - pointer to mode string

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

### 0x27 - PUT (File IO default)
Write the record buffer to the next record in the file.
`PUT #1`

Input:

    BX - filenum - integer value

### 0x28 - PUT (File IO)
Write data to file

Input:

    BX - filenum - integer value
    DX - recordNumber - integer

### 0x29 - WIDTH # (file)
Set the line width of an open file
`WIDTH #filenum, width`

Input:

    BX - filenum - integer value
    DX - width - integer value

### 0x2A - WIDTH (device)
Set the line width of a device
`WIDTH "COM1:", width`

Input:

    BX - device - pointer to string containing device name
    DX - width - integer value

### 0x2B - BEEP
Sounds the speaker at 800 Hz for a quarter of a second (equivalent to
`PRINT CHR$(7)`).

### 0x2C - 0x2E - unused
Point to the "Advanced feature unavailable" stub (error 73).

### 0x2F - CIRCLE (start angle)
Starting angle of arc, in radians. Defaults to 0.

Input:

    BX - pointer to float containing angle

### 0x30 - CIRCLE (end angle)
Ending angle of arc, in radians. Defaults to 2.

Input:

    BX - pointer to float containing angle


### 0x31 - CIRCLE (aspect ratio)
Ratio, in pixels, of the x radius to the y radius.
Defaults to 5/6 in medium resolution, 5/12 in high
resolution; these values generate a circle on the CGA.

Input:

    BX - pointer to float containing ratio

### 0x32 - CLS 
Clear screen

Input: 

    BX - arg - integer value -1 not supplied.

### 0x33 - Add argument to COLOR command

Input:

    BX - arg - integer value

### 0x34 - COLOR arg not supplied
Used to indicate that an argument wasn't supplied. Same handler as 0x43 and 0x5A.

eg. `COLOR ,2`
```asm
INT 0x3e
db  0x34    ; first arg omitted
MOV BX, 2
INT 0x3e
db  0x35    ; COLOR
```

### 0x35 - COLOR
Set Foreground, Background, and Border Colors

Input:

    BX - last argument - integer value

### 0x36 - DRAW
Draws an object according to instructions specified as a string expression.

eg. `DRAW "R10 D10 R20"`

Input:

    BX - drawInstructions - string pointer to draw instructions

### 0x37 - event trapping init
Initializes event trapping. Clears the event tables, sets up the event queue, and installs the
runtime's INT 3 handler used by the `0xCC` event check bytes. Also hooks the keyboard for trapped keys.
The runtime calls this itself at startup. Not seen emitted by the compiler.

### 0x38 - 0x39 - unused
Point to the "Advanced feature unavailable" stub (error 73).

### 0x3A - GET (gfx)
Read pixels from screen into an array.

`DX` is the size of the array in bytes. The runtime checks the image fits and raises
Illegal function call if it doesn't.

eg.
```asm
       1000:1c7d bb  30  00       MOV        BX ,0x30
       1000:1c80 ba  08  00       MOV        DX ,0x8
       1000:1c83 33  c9           XOR        CX ,CX
       1000:1c85 8b  c1           MOV        AX ,CX
       1000:1c87 cd  3e  87       INTB3E     0x87                      INT_3E_87_GET_START_POS
       1000:1c8a bb  dc  00       MOV        BX ,0xdc
       1000:1c8d ba  0f  00       MOV        DX ,0xf
       1000:1c90 cd  3e  88       INTB3E     0x88                      INT_3E_88_GET_END_POS
       1000:1c93 bb  26  49       MOV        BX ,0x4926
       1000:1c96 ba  46  06       MOV        DX ,0x646
       1000:1c99 cd  3e  3a       INTB3E     0x3a                      INT_3E_3A_GET_GFX
```
Input:

    BX - pointer to array to store graphics (array descriptor when DX is 0)
    DX - size of the array in bytes. 0 for a dynamic array

### 0x3B - STEP
Marks the next coordinate as relative to the last graphics point. Sets the relative flag and copies
the last point (or the current world point when WINDOW is active) into the offset that the next
coordinate opcode adds on.

eg. `PSET STEP(1,1)`
```asm
INT 0x3e
db  0x3B    ; STEP
MOV DX, BX
INT 0x3e
db  0x56    ; PSET
```

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

### 0x3E - LCOPY
Legacy GW-BASIC statement (copy screen to printer). The compiler accepts `LCOPY [n]`, but the runtime
routine is a stub that does nothing.

Input:

    BX - n - integer value

### 0x3F - 0x41 - unused
Point to the "Advanced feature unavailable" stub (error 73).

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

### 0x45 - device unavailable stub
Same handler as 0x46, so it always raises error 68 (Device unavailable). Probably the other form of the
cassette MOTOR statement. Not seen emitted (`MOTOR` with no argument compiles to nothing).

### 0x46 - MOTOR
Legacy cassette motor statement. Always raises error 68 (Device unavailable).
`MOTOR n`

Input:

    BX - n - integer value

### 0x47 - unused
Points to the "Advanced feature unavailable" stub (error 73).

### 0x48 - PAINT (color)
Fill an area with a color. The start point is set first with 0x3e `0x8D`.
`PAINT (x,y) [,paint [,border]]`

eg. `PAINT (5,5),1,2`

Input:

    BX - paint - integer attribute. 0xffff when not supplied
    DX - border - integer attribute. 0xffff when not supplied

### 0x49 - PAINT (tile)
Fill an area with a tile pattern. The start point is set first with 0x3e `0x8D`.
`PAINT (x,y), tile$ [,border [,background$]]`

eg. `PAINT (5,5),"ab",3`

Input:

    BX - tile - pointer to tile string
    DX - border - integer attribute. 0xffff when not supplied
    CX - background - pointer to background string. 0xffff when not supplied

### 0x4A - PALETTE
Change Color in the Palette
`PALETTE [attribute, color]`

Input:

    BX - attribute - integer
    DX - color - integer

### 0x4B - PALETTE USING
Change many colors in the palette from an integer array
`PALETTE USING array(index)`

eg. `PALETTE USING p%(0)` with `DIM p%(15)`
```asm
MOV BX, 0x1856   ; p%
XOR DX, DX       ; byte offset of p%(0)
MOV CX, 0x20     ; size of p% in bytes
INT 0x3e
db  0x4B
```

Input:

    BX - array - pointer to array data. If CX is 0xffff, BX points to the array descriptor instead
    DX - offset - byte offset of the starting element
    CX - size - size of the array in bytes. 0xffff for a dynamic array

### 0x4C - PEN ON
Enable light pen read and trapping

### 0x4D - PEN OFF
Disable light pen read and trapping

### 0x4E - PEN STOP
Disable light pen trapping, but keep checking for pen activity

### 0x4F - 0x50 - unused
Point to the "Advanced feature unavailable" stub (error 73).

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

### 0x55 - PRESET
Draw Point on Screen with integer coordinates. Same as PSET but the default color is the background.
`PRESET [STEP] (x,y) [,color]`

When STEP is used it is preceded by 0x3e `0x3B`. When the coordinates aren't integers the point is set
with 0x3e `0x8D` and 0x3e `0x8A` is used instead.

Input:

    BX - x - integer
    DX - y - integer
    CX - color, 0xffff for default (background) color

### 0x56 - PSET
Draw point on screen
`PSET [STEP] (x,y) [,color]`

Input:

    BX - x - integer
    DX - y - integer
    CX - color, 0xffff for default color

### 0x57 - unused
Points to the "Advanced feature unavailable" stub (error 73).

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

### 0x59 - SCREEN arg
Supply an argument to the SCREEN command. Same handler as 0x33 and 0x42.

Input:

    BX - arg - integer value

### 0x5A - SCREEN arg not supplied
Used to indicate that an argument wasn't supplied. Same handler as 0x34 and 0x43.

eg. `SCREEN ,,1`
```asm
INT 0x3e
db  0x5A
INT 0x3e
db  0x5A
MOV BX, AX
INT 0x3e
db  0x5B
```

### 0x5B - SCREEN
Setup screen mode

`SCREEN [mode][,[colorflag]][,[apage]][,[vpage]]`

`mode` passed in `BX`

### 0x5C - STRIG ON
Enable/Disable the STRIG Function. The runtime handler is just a `RETF`.

### 0x5D - STRIG OFF
Disable the STRIG Function. Same `RETF` handler as 0x5C, so it does nothing.

The `0xCC` after the opcode isn't an argument. It is an `INT 3` event check that the compiler emits
when event trapping is in use (see "INT 3 (0xCC) event checks").

```asm
       1000:004f cd  3e           INT        0x3e
       1000:0051 5d              db         5Dh
       1000:0052 cc              ??         CCh
```

### 0x5E - SOUND
Sound the Speaker
`SOUND freq,duration`

Input:

    BX - freq - integer value. In range 37 to 32767
    DX - duration - pointer to float value. In range 0 to 65535

### 0x5F - SOUND (play)
Always follows 0x3e `0x5E`. 0x5E only validates and stores the frequency and duration. This opcode
queues the tone, or stops the current sound when the duration is 0.

`BX` and `DX` are both set to `0xFFFF` by the compiler. The low byte of `DX` is passed to the sound
driver as an extra parameter (0xFF means not supplied, which becomes 0).

### 0x60 - 0x61 - unused
Point to the "Advanced feature unavailable" stub (error 73).

### 0x62 - PCOPY
Copy one screen page to another
`PCOPY sourcepage, destinationpage`

Raises Illegal function call when either page isn't valid for the current screen mode.

Input:

    BX - sourcepage - integer value
    DX - destinationpage - integer value

### 0x63 - unused
Points to the "Advanced feature unavailable" stub (error 73).

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

### 0x6A - STRIG(n) ON
Enable joystick button trap
`STRIG(n) ON`

Input:

    BX - n - button number (0, 2, 4, 6)

### 0x6B - STRIG(n) OFF
Disable joystick button trap
`STRIG(n) OFF`

Input:

    BX - n - button number (0, 2, 4, 6)

### 0x6C - STRIG(n) STOP
Disable joystick button trap, but keep checking
`STRIG(n) STOP`

Input:

    BX - n - button number (0, 2, 4, 6)

### 0x6D - LOCK
Lock a file or a range of records. Needs DOS 3.0 or later, otherwise raises error 73.
Uses INT 21h AH=5Ch.
`LOCK [#]filenum [,{record | [start] TO end}]`

eg. `LOCK #1, 1 TO 5`
```asm
MOV BX, 1        ; file number
MOV DX, 1        ; start record
MOV CX, 5        ; end record
XOR AX, AX       ; flags
INT 0x3e
db  0x6D
```

Record numbers that don't fit in an integer are passed with 0x3e `0x7B` first.

Input:

    BX - filenum - integer value
    DX - start - first record number. integer value
    CX - end - last record number. integer value
    AX - flags
        AH = 0xFF - no record range supplied (whole file)
        AL bit 4 - start record was supplied with 0x3e 0x7B
        AL bit 0 - end record was supplied with 0x3e 0x7B

### 0x6E - UNLOCK
Unlock a file or range of records. Same arguments as LOCK (0x3e `0x6D`).
`UNLOCK [#]filenum [,{record | [start] TO end}]`

### 0x6F - WINDOW (first corner)
First world coordinate for the WINDOW statement. Also turns off the current window.
`WINDOW [[SCREEN] (x1,y1)-(x2,y2)]`

Input:

    BX - x1 - pointer to float
    DX - y1 - pointer to float

### 0x70 - WINDOW (second corner)
Second world coordinate for the WINDOW statement. Sets up the new window.

Input:

    BX - x2 - pointer to float
    DX - y2 - pointer to float
    CX - 0xffff for WINDOW SCREEN (y increases down the screen)

### 0x71 - WINDOW (no arguments)
`WINDOW` with no arguments. Turns off world coordinates.

### 0x72 - VIEW (first corner)
`VIEW [[SCREEN] (x1,y1)-(x2,y2) [,[color] [,border]]]`

Input:

    BX - x1 - integer value
    DX - y1 - integer value

### 0x73 - VIEW (second corner)
Corners are sorted so (x1,y1) is the top left.

Input:

    BX - x2 - integer value
    DX - y2 - integer value

### 0x74 - VIEW
Set up the viewport from the coordinates given with 0x72 and 0x73.

eg. `VIEW (1,1)-(50,50),1,2`

Input:

    BX - color - fill color. 0xffff when not supplied
    DX - border - border color. 0xffff when not supplied
    CX - 0xffff for VIEW SCREEN (coordinates are absolute, not relative to the viewport)

### 0x75 - VIEW (no arguments)
`VIEW` with no arguments. Resets the viewport to the whole screen.

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

### 0x7A - OPEN ACCESS / LOCK clause
Sets the DOS sharing and access mode for the following OPEN (0x3e `0x1E`). Needs DOS 3.0 or later,
otherwise raises error 73.
`OPEN "f" FOR mode [ACCESS access] [lock] AS #n`

eg. `OPEN "f" FOR RANDOM ACCESS READ WRITE SHARED AS #1 LEN=10`
```asm
MOV BX, 0x2      ; RANDOM
INT 0x3e
db  0x20
MOV BX, 0x0304   ; BH = READ WRITE, BL = SHARED
INT 0x3e
db  0x7A
MOV BX, 0x1
MOV AX, DX
MOV DX, 0x1870
MOV CX, 0xA
INT 0x3e
db  0x1E
```

Input:

    BL - lock - integer value
        0 - default (compatibility mode)
        1 - LOCK READ (DOS deny read 0x30)
        2 - LOCK WRITE (DOS deny write 0x20)
        3 - LOCK READ WRITE (DOS deny read/write 0x10)
        4 - SHARED (DOS deny none 0x40)
    BH - access - integer value
        0 - not supplied
        1 - READ
        2 - WRITE
        3 - READ WRITE

### 0x7B - LOCK/UNLOCK record number (long)
Supplies a record number to LOCK/UNLOCK that doesn't fit in an integer. The first call sets the
start record, the second call sets the end record.

eg. `LOCK #1, 100000 TO 200000`
```asm
MOV BX, 0x1876   ; 100000
INT 0x3e
db  0x7B
MOV BX, 0x187a   ; 200000
INT 0x3e
db  0x7B
MOV BX, DX
MOV DX, CX
MOV AX, 0x11     ; both bounds supplied with 0x7B
INT 0x3e
db  0x6D         ; LOCK
```

Input:

    BX - pointer to float or double record number

### 0x7C - SHELL
Execute a DOS command. Uses COMSPEC to run the command processor.
`SHELL [commandstring]`

Input:

    BX - commandstring - pointer to string. Empty string when not supplied

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

### 0x80 - MKDIR
Create subdirectory. INT 21h AH=39h.

Input:

    BX - pathspec - pointer to string path

### 0x81 - RMDIR
Remove subdirectory. INT 21h AH=3Ah.

Input:

    BX - pathspec - pointer to string path

### 0x82 - install break key handler
Installs the runtime's keyboard hook that handles Ctrl-Break, pause and printer echo keys.
Not seen emitted by the compiler.

### 0x83 - save stack pointer before CALL
Only stores `SP` for error recovery. Emitted after the arguments for a SUB call are pushed, when
some of them are temporaries.

eg. `CALL test("hello ", "world", 10)`
```asm
...                  ; push argument pointers
INT 0x3e
db  0x83
PUSH CS
CALL test
```

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

### 0x87 - GET (start position)
x1,y1    Upper left corner of the rectangle to be copied

Seems to also set `AX` and `CX` registers.
Seem to be `0`
eg.
```asm
       1000:1c7d bb  30  00       MOV        BX ,0x30
       1000:1c80 ba  08  00       MOV        DX ,0x8
       1000:1c83 33  c9           XOR        CX ,CX
       1000:1c85 8b  c1           MOV        AX ,CX
       1000:1c87 cd  3e  87       INTB3E     0x87      INT_3E_87_GET_START_POS
```
Input:

    BX - x1 - integer value
    DX - y1 - integer value

### 0x88 - GET (end position)
x2,y2    Lower right corner of the rectangle to be copied

Input:

    BX - x2 - integer value
    DX - y2 - integer value

### 0x89 - PUT (position)
x, y position for top left corner of destination for pixel copy

Input:

    BX - x - integer value
    DX - y - integer value

### 0x8A - PRESET
Draw Point on Screen
`PRESET [STEP] (x,y) [,color]`

Used when the point is set with 0x3e `0x8D` (eg. float coordinates). 0x3e `0x55` is used for integer coordinates.

eg. `PRESET (1.5,2.5),1`

Input:

    BX - color, 0xffff for default (background) color

### 0x8B - PSET (point already set)
Draw Point on Screen
`PSET [STEP] (x,y) [,color]`

Used when the point is set with 0x3e `0x8D` (eg. float coordinates). 0x3e `0x56` is used for integer coordinates.

Input:

    BX - color, 0xffff for default (foreground) color

### 0x8C - CIRCLE
Draws an ellipse on the screen.
`CIRCLE [STEP] (x,y), radius [,[color] [,[start],[end][,aspect]]]`

Input:

    BX - radius - pointer to float
    DX - color - integer value. 0xffff for default if color arg not supplied.

### 0x8D - set point (x, y)

Input:

    CX - xType - type of x argument. -1 = float, 0 = integer
    AX - yType - type of y argument. -1 = float, 0 = integer
    BX - x - integer value
    DX - y - integer value

### 0x8E - 0xA0 - unused
Point to the "Advanced feature unavailable" stub (error 73).

### 0xA1 - VIEW PRINT
Set the text window
`VIEW PRINT [topline TO bottomline]`

Input:

    BX - topline - integer value. 0xffff when no arguments are supplied (reset to the whole screen)
    DX - bottomline - integer value

### 0xA2 - 0xA3 - unused
Point to the "Advanced feature unavailable" stub (error 73).

### 0xA4 - COM(n) STOP (duplicate)
Its table entry points to the same handler as 0x66 COM(n) STOP. Not seen emitted.

### 0xA5 - POKE
Write byte to address in memory

Input:

    BX - address - pointer to float containing address to write to
    DX - byte to write to memory (0 - 255)

---
## 0x3f Interrupt

Seems to be used for variables

### 0x0 - POKE (table overlap)
The 0x3e table runs into this table, so this entry is the same word as 0x3e `0xA5` (POKE)
and calls the same handler. The compiler uses 0x3e `0xA5`.

### 0x1 - array element offset (static array, bounds checked)
Only emitted when compiled with `/D`. Converts subscripts into a byte offset into a static array
and raises error 9 (Subscript out of range) if a subscript is out of bounds.

Subscripts are pushed onto the stack. The array layout follows the opcode as inline data:

    byte - element size in bytes
    byte - number of dimensions * 2
    word - number of elements in each dimension, one word per dimension

eg. `a(i%) = 1` with `DIM a(5)`
```asm
MOV AX, [i%]
PUSH AX
INT 0x3f
db  0x01
db  0x04     ; float - 4 bytes per element
db  0x02     ; 1 dimension
dw  0x0006   ; 6 elements (0 - 5)
MOV DI, AX
ADD DI, 0x1856   ; a
```

Return:

    AX - byte offset of the element

### 0x2 - ON ERROR trap
Enable Error Trapping
`ON ERROR GOTO {linenum | linelabel}`

Input:

    DX - jumpTargetAddr - offset to jump to in current segment. eg. CS:jumpTargetAddr

### 0x3 - ON COM trap
Trap for communications activity
`ON COM(n) GOSUB {linenum | linelabel}`

Input:

    BX - n - com port number (1 or 2)
    DX - jumpTargetAddr - offset to jump to in current segment. eg. CS:jumpTargetAddr

### 0x4 - ON KEY trap
Trap for keypress
`ON KEY(n) GOSUB {linenum | linelabel}`

Input:

    BX - n - key number (1 to 25, plus 30 and 31 on an enhanced keyboard)
    DX - jumpTargetAddr - offset to jump to in current segment. eg. CS:jumpTargetAddr

### 0x5 - ON PEN trap
Trap for light pen activity
`ON PEN GOSUB {linenum | linelabel}`

Input:

    DX - jumpTargetAddr - offset to jump to in current segment. eg. CS:jumpTargetAddr

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

### 0xB - unused
Points to the "Advanced feature unavailable" stub (error 73).

### 0xC - byte range check
Raises Illegal function call if `BX` isn't in the range 0 - 255. Emitted with `/D` before
statements that are compiled inline and take a byte value, eg. `OUT` and `WAIT`.

eg. `OUT 3, k%` compiled with `/D`
```asm
MOV BX, [k%]
INT 0x3f
db  0x0C
MOV AX, BX
MOV DX, 0x3
OUT DX, AL
```

Input:

    BX - integer value to check

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

### 0x11 - SWAP (float)
Exchange the Values of Two Variables
`SWAP var1,var2`

Input:

    DI - var1 - pointer to float
    SI - var2 - pointer to float

### 0x12 - SWAP (double)
Exchange the Values of Two Variables
`SWAP var1,var2`

Input:

    DI - var1 - pointer to double
    SI - var2 - pointer to double

### 0x13 - SWAP (integer)
Exchange the Values of Two Variables
`SWAP var1,var2`

Input:

    DI - var1 - pointer to integer
    SI - var2 - pointer to integer

### 0x14 - SWAP (string)
Exchange the Values of Two Variables
`SWAP var1,var2`

Input:

    DI - var1 - pointer to string
    SI - var2 - pointer to string

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
Convert float to int. Same handler as 0x75 CINT (float), so the value is rounded.

Input:

    SI - pointer to float

Returns:

    BX - converted int value

### 0x1A - double to int
Same handler as 0x76 CINT (double).

Input:

    SI - pointer to double

Returns:

    BX - converted int value

### 0x1B - tmpVarFloat to int
Same handler as 0x77.

Returns:

    BX - converted int value

### 0x1C - tmpVarDouble to int
Same handler as 0x78.

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

### 0x21 - float to unsigned int
Convert float to a 16 bit value. Unlike CINT, values from 32768 to 65535 are allowed and wrap to
the matching negative integer, so the result can be used as an unsigned word. Used for
addresses/segments, eg. `DEF SEG = nnnn` where nnnn is a float. HEX$ and OCT$ of a float use the same code.
```asm
       1000:0040 be  56  18       MOV        SI ,0x1856
       1000:0043 cd  3f           INT        0x3f
       1000:0045 21               ??         21h    !
```

Input:

    SI - pointer to float value

Returns:

    BX - 16 bit value

### 0x22 - tmpVarFloat to unsigned int
Same as 0x21 but converts tmpVarFloat.

Returns:

    BX - 16 bit value

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

### 0x27 - Exponentiation Operator float ^ tempFloatVar
`tmpVarFloat = SI ^ tmpVarFloat`

Input:

    SI - float - base (tempFloatVar is the power)

### 0x28 - Exponentiation Operator double ^ tempDoubleVar
`tmpVarDouble = SI ^ tmpVarDouble`

Input:

    SI - double - base (tempDoubleVar is the power)

### 0x29 - Exponentiation Operator stack ^ tempFloatVar (3 param)
`tmpVarFloat = floatStackValue ^ tmpVarFloat`. Second byte is the temp slot.

### 0x2A - Exponentiation Operator stack ^ tempDoubleVar (3 param)
`tmpVarDouble = doubleStackValue ^ tmpVarDouble`. Second byte is the temp slot.

eg. `z# = b#(1,1) ^ b#(2,2)`
```asm
... load b#(1,1) into tmpVarDouble
INT 0x3f
db  0x72, 0x82   ; slot2 = tmpVarDouble
... load b#(2,2) into tmpVarDouble
INT 0x3f
db  0x2A, 0x82   ; tmpVarDouble = slot2 ^ tmpVarDouble
```

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

### 0x33 - RESTORE
Reset the DATA pointer to the first DATA item. READ (0x3f `0xD`-`0x10`) does the same
automatically the first time it is used.

### 0x34 - RESTORE line
Reset the DATA pointer to the first DATA item at or after the given line.
`RESTORE linenum`

eg. `RESTORE 20`
```asm
MOV BX, 0x3b
INT 0x3f
db  0x34
```

Input:

    BX - key of the DATA line, generated by the compiler (not the BASIC line number).
         DATA lines are searched for the first one whose key is >= BX.

### 0x35 - SPC
Skip n Spaces in a PRINT statement
`PRINT SPC(n)`

n is taken modulo the output width. Used for screen, LPRINT and PRINT # output.

Input:

    BX - n -integer value. Number of spaces to skip.

### 0x36 - SPC (byte)
Like 0x35 but `BX` must be 0 - 255 (else Illegal function call) and isn't taken modulo the width.
Not seen emitted by the compiler.

Input:

    BX - n - integer value. Number of spaces to skip.

### 0x37 - TAB
Tab to a specified position in a PRINT statement
`PRINT TAB(n)`

Moves to column n. If the current column is already past n, a newline is output first.
n is taken modulo the output width.

eg. `PRINT SPC(7); TAB(8);`
```asm
INT 0x3f
db  0xBC
MOV BX, 7
INT 0x3f
db  0x35     ; SPC
...
MOV BX, 8
INT 0x3f
db  0x37     ; TAB
```

Input:

    BX - n - integer value. Column to move to (1 based).

### 0x38 - TAB (byte)
Like 0x37 but `BX` must be 0 - 255 (else Illegal function call) and isn't taken modulo the width.
Not seen emitted by the compiler.

Input:

    BX - n - integer value. Column to move to (1 based).

### 0x39 - start function
Marks the start of a function. Used for DEF FN functions.

### 0x3A - end function
Marks the end of a function. Used for DEF FN functions.

### 0x3B - copy string to temp
Makes a new temporary string holding a copy of the string. Not seen emitted yet.

Input:

    BX - pointer to string

Return:

    BX - pointer to new temporary string

### Dynamic array element opcodes
Numeric `$DYNAMIC` arrays are stored outside the data segment. The elements are reached through
the array descriptor:

    word [BX]     - segment of array data (or offset when bit 7 of the type byte is set)
    byte [BX+2]   - element type. 1 = integer, 2 = float, 3 = double, 4 = string. bit 7 set = array is in DS
    byte [BX+3]   - number of dimensions
    word [BX+0xA] - number of elements in each dimension

Integers are passed in `AX`. Floats go through tmpVarFloat and doubles through tmpVarDouble.

There are two sets of opcodes. With `/D` the subscripts are pushed onto the stack and bounds checked
(0x3C - 0x41). Without `/D` the compiler works out the byte offset itself and passes it in `DX` (0xC4 - 0xC9).

eg. `x = a(i%)` (no `/D`)
```asm
MOV DX, [i%]
SHL DX, 1
SHL DX, 1        ; byte offset of a(i%)
MOV BX, 0x1856   ; a descriptor
INT 0x3f
db  0xC4         ; tmpVarFloat = a(i%)
MOV DI, 0x1878
INT 0x3f
db  0x7D         ; x = tmpVarFloat
```

### 0x3C - load dynamic array element (bounds checked)
Same as 0xC4 but the subscripts are pushed onto the stack.

Input:

    BX - pointer to array descriptor
    stack - subscripts

### 0x3D - store dynamic array element (bounds checked)
Same as 0xC5 but the subscripts are pushed onto the stack.

Input:

    BX - pointer to array descriptor
    stack - subscripts

### 0x3E - set dynamic array element target (bounds checked)
Same as 0xC6 but the subscripts are pushed onto the stack.

Input:

    BX - pointer to array descriptor
    stack - subscripts

### 0x3F - SWAP dynamic array elements (bounds checked)
Same as 0xC7 but the subscripts are pushed onto the stack.

Input:

    BX - pointer to array descriptor
    stack - subscripts

### 0x40 - SWAP dynamic array element with variable
Swaps the element set by 0x3f `0x3E`/`0xC6` with a variable. Same handler as 0xC8.

eg. `SWAP a(i%), x`

Input:

    SI - pointer to variable

### 0x41 - VARPTR dynamic array element (bounds checked)
Same as 0xC9 but the subscripts are pushed onto the stack.

Input:

    BX - pointer to array descriptor
    stack - subscripts

### 0x42 - array element offset (dynamic array, bounds checked)
Like 0x3f `0x01` but takes the dimensions from an array descriptor instead of inline data.
Raises error 9 (Subscript out of range) if the array isn't allocated or a subscript is out of range.
Not seen emitted yet.

Input:

    BX - pointer to array descriptor
    stack - subscripts

Return:

    AX - byte offset of the element

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

### 0x53 - start subroutine
SUB prologue. Emitted at the start of each `SUB ... STATIC`.
- `PUSH BP / MOV BP, SP`
- reserves the runtime's local frame space on the stack and checks for stack overflow (error 7 Out of memory)
- `[BP-2]` = DS, `[BP-4]` = 0 (GOSUB nesting count for this frame)
- increments the SUB nesting level

Arguments are passed as pointers on the stack and read with `[BP+6]`, `[BP+8]`...

### 0x54 - end subroutine
SUB epilogue. Restores `SP` and `BP` and decrements the SUB nesting level. Always followed by
a `RETF n`. The runtime reads n from the instruction so it knows how much stack the
arguments use.

eg.
```basic
sub test static
	print "Hello"
end sub
```
```asm
INT 0x3f
db  0x53
INT 0x3f
db  0xBC
MOV BX, 0x1856
INT 0x3f
db  0x6E
INT 0x3e
db  0x79
INT 0x3f
db  0x54
RETF 0x0000
```

### 0x55 - concatenate strings
Concatenate two strings together. Only `AX` and `BX` are used. `CX` is preserved, so setting it in
the example is just the compiler moving values around. Raises Illegal function call if the result would be longer than 32767 characters.
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

### 0x58 - GOSUB
GOSUB used in `/D`, `/V` and `/W` builds (otherwise GOSUB is a plain `CALL`). The target address
follows the opcode as an inline word. Checks for stack overflow, increments the GOSUB count
in the current frame (`[BP-4]`), and jumps to the target with the return address on the stack.

eg. `GOSUB 100`
```asm
INT 0x3f
db  0x58
dw  0x008c   ; target address CS:008c
```

### 0x59 - line trace / break check
Emitted before each statement when compiled with `/D`. Checks for Ctrl-Break, and when TRON
is active prints `[n]` where n is the line number of the statement (looked up from the return address).

### 0x5A - LINE INPUT
Read an entire line into a string variable, ignoring delimiters. The prompt or file is set
up first with 0x3f `0xB5` (keyboard) or 0x3f `0xB6` (file).
`LINE INPUT [;] ["prompt";] stringvar`
`LINE INPUT #filenum, stringvar`

eg. `LINE INPUT "p"; a$`
```asm
MOV BX, 0x1860   ; "p"
INT 0x3f
db  0xB5, 0x02
MOV BX, 0x1856   ; a$
INT 0x3f
db  0x5A
```

Input:

    BX - pointer to destination string variable

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

### 0x5F - RETURN line
`RETURN {linenum | linelabel}`. Removes the GOSUB return address from the stack and decrements
the GOSUB count. It is followed by a `JMP` to the target line. Raises error 3 (RETURN without GOSUB)
if there is no GOSUB active.

eg. `RETURN 200`
```asm
INT 0x3f
db  0x5F
JMP line200
```

### 0x60 - RETURN
RETURN from gosub. Used in `/D`, `/V` and `/W` builds (otherwise RETURN is a plain `RET`).
Decrements the GOSUB count and returns to the address pushed by GOSUB (0x3f `0x58`).
Raises error 3 (RETURN without GOSUB) if there is no GOSUB active. Also returns from event trap handlers.

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

### 0x70 - PUSH double
Push double onto stack.

Input:

    SI - pointer to double value

### 0x71 - Push float temp var onto stack (3 param)
Pushes the current value of float temp var onto a stack.
Has a second byte operand which appears to start at 0x80 and increment with each invocation.

### 0x72 - Push double temp var onto stack (3 param)
Pushes the current value of double temp var onto a stack.
Has a second byte operand which appears to start at 0x80 and increment with each invocation.

### 0x74 - convert float temp var to double temp var
`tmpVarDouble = tmpVarFloat`. As the temp vars overlap this just zeroes the low 4 bytes of the double (`DS:16`-`DS:19`).

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

### 0x77 - CINT (tmpVarFloat)
Convert tmpVarFloat to integer (rounded). Raises Overflow if out of range.

Returns:

    BX - integer value

### 0x78 - CINT (tmpVarDouble)
Convert tmpVarDouble to integer (rounded). Raises Overflow if out of range.

Returns:

    BX - integer value

### 0x79 - CSNG
convert double to float and store in internal float

Input:

    SI - double pointer

### 0x7A - convert temp var from double to float
`tmpVarFloat = CSNG(tmpVarDouble)`. Rounds the double to single precision. 0x79 copies the double
into tmpVarDouble and then runs the same code.

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

### 0x8D - Division stack / temp var (float) (3 param)
`tmpVarFloat = floatStackValue / tmpVarFloat`. Second byte is the temp slot.

### 0x8E - Division stack / temp var (double) (3 param)
`tmpVarDouble = doubleStackValue / tmpVarDouble`. Second byte is the temp slot.

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

### 0x9E - Subtract tmpVarDouble from doubleStackValue (3 param)
Has second byte operand which starts at 0x80 and increments.
`tmpVarDouble = doubleStackVal - tmpVarDouble`

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

### 0xA3 - compare float with temp var
Compare float (left hand side) with tmpVarFloat (right hand side) and set x86 flags accordingly.

Input:

    SI - float - pointer to float

### 0xA4 - compare double with temp var
Compare double (left hand side) with tmpVarDouble (right hand side) and set x86 flags accordingly.

Input:

    SI - double - pointer to double

### 0xA5 - Compare tmpVarFloat and stack float value
Compare floatStackValue (left hand side) with tmpVarFloat (right hand side). Second byte is the temp slot.

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

### 0xA6 - Compare tmpVarDouble and stack double value
Compare doubleStackValue (left hand side) with tmpVarDouble (right hand side). Second byte is the temp slot.

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

### 0xB1 - tmpVarFloat negation
`tmpVarFloat = -tmpVarFloat`

eg. `a = -TIMER`
```asm
INT 0x3d
db  0x43     ; TIMER
INT 0x3f
db  0xB1
MOV DI, 0x1856
INT 0x3f
db  0x7D
```

### 0xB2 - tmpVarDouble negation
`tmpVarDouble = -tmpVarDouble`

### 0xB3 - FIELD start
Selects the file for the following FIELD var opcodes (0x3f `0xB4`) and resets the field position to
the start of the file's record buffer. Raises error 54 (Bad file mode) if the file isn't an open
random file.
`FIELD [#]filenum, width AS stringvar [,width AS stringvar]...`

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
    second byte - flags
        bit 0 - `INPUT;` form. Don't output a newline after the input
        bit 1 - don't print "? " after the prompt (prompt followed by a comma, or LINE INPUT)

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

### 0xB9 - INPUT load dynamic array element
Loads the parsed value into a `$DYNAMIC` array element. The element is selected first with
0x3f `0xC6` (or `0x3E` with `/D`).

eg. `INPUT a(4)`
```asm
MOV BX, 0x18b0
INT 0x3f
db  0xB5, 0x00
INT 0x3f
db  0xB7, 0x01, 0x02
MOV BX, 0x1856   ; a descriptor
MOV DX, 0x10     ; byte offset of a(4)
INT 0x3f
db  0xC6
INT 0x3f
db  0xB9
```

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

### 0xBF - PRINT # USING
Formatted output to a file
`PRINT #filenum, USING strexpr; exprlist [;]`

Print params are separate opcodes same as PRINT

eg. `PRINT #1, USING "##"; 5`
```asm
XCHG AX, DX      ; DX = file number
MOV BX, 0x1884   ; "##"
INT 0x3f
db  0xBF
MOV DX, BX
MOV BX, 5
INT 0x3f
db  0x6D
INT 0x3e
db  0x79
```

Input:

    DX - filenum - integer value
    BX - strexpr - pointer to formatting string

### 0xC0 - LPRINT
Start printing to the printer (LPT1:). Print params are separate opcodes same as PRINT,
followed by 0x3e `0x79`.

### 0xC1 - LPRINT USING
Formatted output to the printer (LPT1:)
`LPRINT USING strexpr; exprlist [;]`

Input:

    BX - strexpr - pointer to formatting string

### 0xC2 - 0xC3 - unused
Point to the "Advanced feature unavailable" stub (error 73).

### 0xC4 - load dynamic array element
Load an element of a `$DYNAMIC` numeric array (see "Dynamic array element opcodes").
Result goes to `AX` (integer), tmpVarFloat (float) or tmpVarDouble (double).

Input:

    BX - pointer to array descriptor
    DX - byte offset of element

### 0xC5 - store dynamic array element
Store into an element of a `$DYNAMIC` numeric array. Value comes from `AX` (integer),
tmpVarFloat (float) or tmpVarDouble (double).

eg. `c%(j%) = 2`
```asm
MOV DX, [j%]
SHL DX, 1
MOV BX, 0x186c   ; c% descriptor
MOV AX, 2
INT 0x3f
db  0xC5
```

Input:

    BX - pointer to array descriptor
    DX - byte offset of element
    AX - integer value (integer arrays)

### 0xC6 - set dynamic array element target
Stores the far address of an element for a following SWAP (0x3f `0xC7`/`0x40`) or INPUT (0x3f `0xB9`).

Input:

    BX - pointer to array descriptor
    DX - byte offset of element

### 0xC7 - SWAP dynamic array elements
Swap the element set by 0x3f `0xC6` with another element of a dynamic array.

eg. `SWAP a(1), a(2)`
```asm
MOV DX, 0x8      ; a(2)
INT 0x3f
db  0xC6
MOV DX, 0x4      ; a(1)
INT 0x3f
db  0xC7
```

Input:

    BX - pointer to array descriptor
    DX - byte offset of element

### 0xC8 - SWAP dynamic array element with variable
Same handler as 0x3f `0x40`.

Input:

    SI - pointer to variable

### 0xC9 - VARPTR dynamic array element
Returns the address of a `$DYNAMIC` array element as an offset from DS. Can be larger than 64K,
so the result is stored as a float in tmpVarFloat.

eg. `v = VARPTR(a(3))`

Input:

    BX - pointer to array descriptor
    DX - byte offset of element

### 0xCA - Load float from stack into temp var (2 param)
`tmpVarFloat = floatStackValue`. Second byte is the temp slot. Opposite of 0x3f `0x71`.

### 0xCB - Load double from stack into temp var (2 param)
`tmpVarDouble = doubleStackValue`. Second byte is the temp slot. Opposite of 0x3f `0x72`.
