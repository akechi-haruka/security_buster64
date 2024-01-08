.model flat
.486

.data
extern _PA : dword
.code
_ASMJmpToPA proc
jmp dword ptr [_PA]
_ASMJmpToPA endp
end
