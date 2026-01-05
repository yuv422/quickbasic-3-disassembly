# QuickBasic 3 disassembly & reverse engineering notes

<!-- TOC -->
* [QuickBasic 3 disassembly & reverse engineering notes](#quickbasic-3-disassembly--reverse-engineering-notes)
  * [BRUN30.EXE Runtime](#brun30exe-runtime)
  * [DEF FN](#def-fn)
  * [BASIC Compiled interrupt functions](#basic-compiled-interrupt-functions)
  * [0x3d Interrupt](#0x3d-interrupt)
    * [0x1 - FIX (float)](#0x1---fix-float)
    * [0x2 - FIX (double)](#0x2---fix-double)
    * [0x5 - ?? Seen in CHR$(42) example.](#0x5----seen-in-chr42-example)
    * [0x6 - INKEY$](#0x6---inkey)
    * [0x18 - CVI](#0x18---cvi)
    * [0x19 - CVS](#0x19---cvs)
    * [0x1A - CVD](#0x1a---cvd)
    * [0x1B - MKI$](#0x1b---mki)
    * [0x1C - MKS$](#0x1c---mks)
    * [0x1D - MKD$](#0x1d---mkd)
    * [0x1E - ERL](#0x1e---erl)
    * [0x1F - ERR](#0x1f---err)
    * [0x23 - DATE$](#0x23---date)
    * [0x25 - CSRLIN](#0x25---csrlin)
    * [0x2F - EOF](#0x2f---eof)
    * [0x36 - COS](#0x36---cos)
    * [0x37 - EXP](#0x37---exp)
    * [0x3D - COS (double)](#0x3d---cos-double)
    * [0x3E - EXP (double)](#0x3e---exp-double)
    * [0x48 - ERDEV](#0x48---erdev)
    * [0x49 - ERDEV$](#0x49---erdev)
    * [0x4A - COMMAND$](#0x4a---command)
    * [0x62 - PEEK](#0x62---peek)
    * [0x63 - FRE (string)](#0x63---fre-string)
    * [0x64 - FRE (num)](#0x64---fre-num)
  * [0x3e Interrupt](#0x3e-interrupt)
    * [0x1 - END](#0x1---end)
    * [0x2 - (END PROGRAM)](#0x2---end-program)
    * [0xB - CLEAR](#0xb---clear)
    * [0xC - CLEAR (no stack args)](#0xc---clear-no-stack-args)
    * [0xE - CHAIN](#0xe---chain)
    * [0x11 - ERROR](#0x11---error)
    * [0x14 - DEF SEG (default)](#0x14---def-seg-default)
    * [0x15 - DEF SEG](#0x15---def-seg)
    * [0x17 - DATE$ (write)](#0x17---date-write)
    * [0x19 - BLOAD (offset from file)](#0x19---bload-offset-from-file)
    * [0x1A - BLOAD](#0x1a---bload)
    * [0x1B - BSAVE](#0x1b---bsave)
    * [0x1C - FILES](#0x1c---files)
    * [0x1D - FILES (no argument)](#0x1d---files-no-argument)
    * [0x1E - OPEN](#0x1e---open)
    * [0x20 - ?? seen in OPEN test](#0x20----seen-in-open-test)
    * [0x21 - CLOSE](#0x21---close)
    * [0x22 - CLOSE (close all open files)](#0x22---close-close-all-open-files)
    * [0x25 - GET (default)](#0x25---get-default)
    * [0x26 - GET](#0x26---get)
    * [0x28 - PUT (File IO)](#0x28---put-file-io)
    * [0x2B - BEEP](#0x2b---beep)
    * [0x32 - CLS](#0x32---cls-)
    * [0x33 - Add argument to COLOR command](#0x33---add-argument-to-color-command)
    * [0x35 - COLOR](#0x35---color)
    * [0x36 - DRAW](#0x36---draw)
    * [0x3B - STEP ??](#0x3b---step-)
    * [0x46 - ENVIRON$ (name)](#0x46---environ-name)
    * [0x47 - ENVIRON$ (ordinal)](#0x47---environ-ordinal)
    * [0x58 - PUT (graphics)](#0x58---put-graphics)
    * [0x5B - SCREEN](#0x5b---screen)
    * [0x64 - COM(n) ON](#0x64---comn-on)
    * [0x65 - COM(n) OFF](#0x65---comn-off)
    * [0x66 - COM(n) STOP](#0x66---comn-stop)
    * [0x79 - PRINT](#0x79---print)
    * [0x7E - ENVIRON](#0x7e---environ)
    * [0x7F - CHDIR](#0x7f---chdir)
    * [0x84 - LINE (start position)](#0x84---line-start-position)
    * [0x85 - LINE (end position)](#0x85---line-end-position)
    * [0x86 - LINE](#0x86---line)
    * [0x89 - PUT (position)](#0x89---put-position)
    * [0x8C - CIRCLE](#0x8c---circle)
    * [0x8D - ?? set point (x, y)](#0x8d----set-point-x-y)
    * [0xA5 - POKE](#0xa5---poke)
  * [0x3f Interrupt](#0x3f-interrupt)
    * [0xA - RSET](#0xa---rset)
    * [0xD - READ (float)](#0xd---read-float)
    * [0xE - READ (double)](#0xe---read-double)
    * [0xF - READ (integer)](#0xf---read-integer)
    * [0x10 - READ (string)](#0x10---read-string)
    * [0x21 - ?? push float to stack](#0x21----push-float-to-stack)
    * [0x43 - DIM (dynamic float)](#0x43---dim-dynamic-float)
    * [0x44 - DIM (dynamic double)](#0x44---dim-dynamic-double)
    * [0x45 - DIM (dynamic integer)](#0x45---dim-dynamic-integer)
    * [0x46 - DIM (dynamic string)](#0x46---dim-dynamic-string)
    * [0x47 - ERASE (dynamic)](#0x47---erase-dynamic)
    * [0x4B - ERASE (static)](#0x4b---erase-static)
    * [0x53 - ?? start subroutine](#0x53----start-subroutine)
    * [0x54 - ?? end subroutine](#0x54----end-subroutine)
    * [0x55 - concatenate strings](#0x55---concatenate-strings)
    * [0x56 - ?? used in b# = CDBL(a%)](#0x56----used-in-b--cdbla)
    * [0x57 - push integer to stack](#0x57---push-integer-to-stack)
    * [0x5B - LSET](#0x5b---lset)
    * [0x61 - Copy string](#0x61---copy-string)
    * [0x62 - Compare strings](#0x62---compare-strings)
    * [0x73 - ??](#0x73---)
    * [0x75 - CINT (float)](#0x75---cint-float)
    * [0x75 - CINT (double)](#0x75---cint-double)
    * [0x77 - pop integer off stack](#0x77---pop-integer-off-stack)
    * [0x78 - POP double as integer ??](#0x78---pop-double-as-integer-)
    * [0x79 - CSNG](#0x79---csng)
    * [0x7B - Copy float from one var to another](#0x7b---copy-float-from-one-var-to-another)
    * [0x7C - Copy double from one var to another](#0x7c---copy-double-from-one-var-to-another)
    * [0x7D - POP float](#0x7d---pop-float)
    * [0x7E - POP double](#0x7e---pop-double)
    * [0x7F - Addition (float)](#0x7f---addition-float)
    * [0x80 - Addition (double)](#0x80---addition-double)
    * [0x9F - compare floats](#0x9f---compare-floats)
    * [0xA0 - compare doubles](#0xa0---compare-doubles)
    * [0xB3 - ?? FIELD start maybe](#0xb3----field-start-maybe)
    * [0xB4 - FIELD var](#0xb4---field-var)
    * [0xBB - ASC](#0xbb---asc)
<!-- TOC -->

## BRUN30.EXE Runtime

## DEF FN
Functions are `CALL`'d and return with `RET` The return value is pushed onto the stack.

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

### 0x5 - ?? Seen in CHR$(42) example.
BX contains the integer value

### 0x6 - INKEY$
Loads last keypress

Returns:

    BX - pointer to string containing last keypress

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

### 0x23 - DATE$
Loads system date into internal string. Date is in the format "MM-DD-YYYY"

### 0x25 - CSRLIN
Line Position of Cursor.

Return:

    BX - linPos - integer value

### 0x2F - EOF
Checks for end of file.
eg. `y = EOF(filenum)`

Input:

    BX - filenum - integer containing file handle

Returns:

    BX - status - integer containing status. EOF returns -1
                (true); otherwise, it returns 0 (false).

### 0x36 - COS
Calculate cosine and store internally

Input:
    BX - angle in radians - pointer to float

### 0x37 - EXP
Returns e (the base of natural logarithms) to the power of supplied numexpr.

Pushes result to stack

Input:

    BX - numexpr - pointer to float

### 0x3D - COS (double)
Calculate cosine and store internally

Input:
BX - angle in radians - pointer to double

### 0x3E - EXP (double)
Returns e (the base of natural logarithms) to the power of supplied numexpr.

Pushes result to stack

Input:

    BX - numexpr - pointer to double

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

----
0x3e Interrupt
----
Seems to be used for commands.

### 0x1 - END
Terminate Program

### 0x2 - (END PROGRAM)
Found at the end of the program. Clean up and exit to DOS

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

### 0x20 - ?? seen in OPEN test
Seems to pass a value in BX
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

### 0x21 - CLOSE
Close File or Device

Input:

    BX - filenum - integer value

### 0x22 - CLOSE (close all open files)
Close File or Device

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

    BX - x - integer value
    DX - y - integer value

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

### 0x8C - CIRCLE
`CIRCLE [STEP] (x,y), radius [,[color] [,[start],[end][,aspect]]]`

Draws an ellipse on the screen.
(x, y) seems to be set using INT 0x3E 0x8D 

*TODO* Investigate optional arguments

Input:

    BX - radius - pointer to float

### 0x8D - ?? set point (x, y)

Input:

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

### 0x21 - ?? push float to stack
Push float onto stack. Seen in `DEF SEG = nnnn` where nnnn is a float
```asm
       1000:0040 be  56  18       MOV        SI ,0x1856
       1000:0043 cd  3f           INT        0x3f
       1000:0045 21               ??         21h    !
```

Input:

    SI - pointer to float value

### 0x43 - DIM (dynamic float)
Create dynamic array

Array dimensions are pushed to the stack as Integers (left to right order)

Second byte of data after INT instruction.
*TODO* Work out what the value means. Currently only observed to be 0x02.

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

Second byte of data after INT instruction.
*TODO* Work out what the value means. Currently only observed to be 0x02.

Input:

    BX - pointer to array

### 0x45 - DIM (dynamic integer)
Create dynamic array

Array dimensions are pushed to the stack as Integers (left to right order)

Second byte of data after INT instruction.
*TODO* Work out what the value means. Currently only observed to be 0x02.

Input:

    BX - pointer to array

### 0x46 - DIM (dynamic string)
Create dynamic array

Array dimensions are pushed to the stack as Integers (left to right order)

Second byte of data after INT instruction.
*TODO* Work out what the value means. Currently only observed to be 0x02.

Input:

    BX - pointer to array

### 0x47 - ERASE (dynamic)
Erase dynamic array

*TODO* work out arguments.

### 0x4B - ERASE (static)
Erase bytes in array to zero.

Input:

    DI - pointer to array
    CX - number of bytes to erase

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

### 0x56 - ?? used in b# = CDBL(a%)
Integer value pointer in BX

### 0x57 - push integer to stack

Input:

    BX - integer value

### 0x5B - LSET
Move string into random access FIELD variable. Left justified.

Input:

    BX - RHS pointer to source string
    DX - LHS pointer to field string

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

### 0x73 - ??
Seen between 0x7B and 0x7E


### 0x75 - CINT (float)
Convert float to integer

Input:

    SI - float pointer

Output:

    BX - integer value


### 0x75 - CINT (double)
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

### 0xB3 - ?? FIELD start maybe

Input:

    BX - filenum - integer

### 0xB4 - FIELD var
Allocates space for variables in a random-access file buffer.

Input:

    BX - pointer to field string 
    DX - fieldWidth - integer

### 0xBB - ASC
Returns the ASCII value of the first character of a string expression.
string passed in BX
ASCII val returned in BX