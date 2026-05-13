---
layout: post
title: "2026 핵테온 후기"
date: 2026-05-13 09:00:00 +0900
categories: ["CW"]
tags: [ctf, wargame, reversing, writeup]
---

2026년 핵테온 예선전 초급A로 신청을 하게 되었다. 나는 리버싱 문제 두개를 풀었다. 아래는 그 두 문제에 대한 WriteUp 및 Upsolving이다.
![hto](/image/2026-05-13/hto1.png)
![hto](/image/2026-05-13/hto2.png)

# Recover It!

```text
My flag has gone by ransomware T.T
But hacker is dumb, i think.
Can you recover it?
```

제공 파일을 압축 해제해 보면 `prob` 이라는 실행 파일을 확인할 수 있다.

```bash
# file prob
prob: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=bd9e59e8a6e03acc40a04437f6f5d2e34a704b7d, for GNU/Linux 3.2.0, not stripped
```

`file` 명령어로 파일 정보를 확인해보면 해당 파일은 stripped 되지 않은 리눅스 실행 파일이다.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int i; // [rsp+Ch] [rbp-74h]
  char s[8]; // [rsp+10h] [rbp-70h] BYREF
  __int64 v6; // [rsp+18h] [rbp-68h]
  __int64 v7; // [rsp+20h] [rbp-60h]
  __int64 v8; // [rsp+28h] [rbp-58h]
  __int64 v9; // [rsp+30h] [rbp-50h]
  __int64 v10; // [rsp+38h] [rbp-48h]
  __int64 v11; // [rsp+40h] [rbp-40h]
  __int64 v12; // [rsp+48h] [rbp-38h]
  __int64 v13; // [rsp+50h] [rbp-30h]
  __int64 v14; // [rsp+58h] [rbp-28h]
  __int64 v15; // [rsp+60h] [rbp-20h]
  __int64 v16; // [rsp+68h] [rbp-18h]
  int v17; // [rsp+70h] [rbp-10h]
  unsigned __int64 v18; // [rsp+78h] [rbp-8h]

  v18 = __readfsqword(0x28u);
  *(_QWORD *)s = 0;
  v6 = 0;
  v7 = 0;
  v8 = 0;
  v9 = 0;
  v10 = 0;
  v11 = 0;
  v12 = 0;
  v13 = 0;
  v14 = 0;
  v15 = 0;
  v16 = 0;
  v17 = 0;
  printf("Input: ");
  __isoc99_scanf("%99s", s);
  if ( strlen(s) == 64 )
  {
    for ( i = 0; i <= 0x3F; ++i )
      s[i] ^= (_BYTE)i + 103;
    if ( !memcmp(s, &cmptable, 0x40u) )
      puts("Correct!");
    else
      puts("Wrong..");
    return 0;
  }
  else
  {
    puts("Input length mismatch!");
    return 1;
  }
}
```

위는 ida를 사용해서 디컴파일한 `main` 함수이다. 실행 순서를 대강 확인해보면 아래와 같다.

1. 변수 `s`에 입력값 받는다.
2. 만약 `s`의 크기가 64bytes라면 `s`의 각 요소를 `i + 103`과 XOR연산을 0x40번 수행한다.
3. for문이 다 돌아간 후, 해당 `s` 값과 `cmptable` 값을 0x40bytes 만큼 비교하고, 값이 같다면 “Correct!”를 반환한다.

`main` 함수만 봤을 때 입력값을 맞춰서 “Correct!”를 출력시키는 게 목표인 전형적인 리버싱 역연산 문제로 보인다. 역연산 코드는 `cmptable` 값을 다시 `i + 103`과 XOR연산을 0x40번 수행시키면 된다.

```python
cmptable = bytes.fromhex(
    "55 5A 0A 59 5F 09 55 5F 56 14 43 4A 43 44 11 14 "
    "41 48 4C 1E 42 1A 19 1C 1C B9 E3 E3 BA E5 E7 B1 "
    "B6 EC BF E8 B2 BD BA BB EB A6 F3 A1 F1 A4 A4 A0 "
    "F4 AC A0 F9 FF A5 A9 A8 AD 94 C7 97 97 91 C6 95"
)

answer = bytes(b ^ (i + 0x67) for i, b in enumerate(cmptable))
answer_str = answer.decode()

print("input =", answer_str)
```

해당 코드를 실행시켜서 결과를 양식에 맞게 제출하면 플래그를 얻을 수 있었다.


# Brain Outside

```text
Where is code?
```

문제에서는 압축 파일과 nc 주소를 제공하였다. 제공 파일 압축을 해제하면 `client` 실행 파일을 확인할 수 있다.

```bash
# file client
client: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=d5e39e7c5a8ec7ef3f76e06a25c5804bf1332b58, for GNU/Linux 3.2.0, stripped
```

파일 정보를 확인해보면 해당 파일은 stripped된 64bit ELF 파일이다.

```bash
# objdump -s -j .rodata client | rg -n 'Usage|socket|connect|mmap'
6: 486010 55736167 653a2025 73203c69 703e203c  Usage: %s <ip> <
7: 486020 706f7274 3e0a0073 6f636b65 7400496e  port>..socket.In
9: 486040 6f6e6e65 6374006d 6d617000 2e2e2f73  onnect.mmap.../s
26: 486150 5f69735f 6d6d6170 70656420 28702900  _is_mmapped (p).
...
```

```c
__int64 __fastcall sub_4018F0(int a1, _QWORD *a2, __int64 a3, __int64 a4, int a5, int a6)
{
  __int64 result; // rax
  unsigned int v7; // ebp
  __int64 v8; // rdi
  __int16 v9; // ax
  __int64 v10; // rsi
  __int64 v11; // rax
  __int64 (*v12)(void); // rbx
  __int64 (*v13)(void); // rdi
  unsigned __int64 v14; // rbx
  __int64 v15; // rax
  unsigned __int64 v16; // r15
  __int64 v17; // rax
  unsigned int v18; // [rsp+0h] [rbp-68h] BYREF
  int v19; // [rsp+4h] [rbp-64h] BYREF
  __int64 v20; // [rsp+8h] [rbp-60h] BYREF
  __int16 v21; // [rsp+10h] [rbp-58h] BYREF
  _QWORD v22[2]; // [rsp+12h] [rbp-56h] BYREF
  unsigned __int64 v23; // [rsp+28h] [rbp-40h]

  v23 = __readfsqword(0x28u);
  if ( a1 != 3 )
  {
    sub_41D4E0((_DWORD)off_4B26C8, 2, (unsigned int)"Usage: %s <ip> <port>\n", *a2, a5, a6, v18);
LABEL_3:
    result = 1;
    goto LABEL_4;
  }
  v7 = sub_41D470(2, 1, 0);
  if ( (v7 & 0x80000000) != 0 )
  {
    sub_401282("socket");
    goto LABEL_3;
  }
  v8 = a2[2];
  v22[0] = 0;
  *(_QWORD *)((char *)v22 + 6) = 0;
  v21 = 2;
  v9 = sub_404EB0(v8, 0, 10);
  v10 = a2[1];
  LOWORD(v22[0]) = __ROL2__(v9, 8);
  if ( (unsigned int)sub_41D9A0(2, v10, (char *)v22 + 2) != 1 )
  {
    sub_4066E0("Invalid address\n", 1, 16, off_4B26C8);
    goto LABEL_3;
  }
  if ( (int)sub_41D3D0(v7, &v21, 16) < 0 )
  {
    sub_401282("connect");
    goto LABEL_3;
  }
LABEL_9:
  if ( (int)sub_401C40(v7, &v18, 4) >= 0 )
  {
    v11 = sub_41CC80(0);
    v12 = (__int64 (*)(void))v11;
    if ( v11 == -1 )
    {
      sub_401282("mmap");
    }
    else if ( (int)sub_401C40(v7, v11, v18) < 0 )
    {
      sub_41CD70(v12, v18);
    }
    else
    {
      v13 = v12;
      v20 = v12();
      v14 = 0;
      sub_41CD70(v13, v18);
      v19 = 8;
      while ( 1 )
      {
        v15 = sub_41C290(v7, (char *)&v19 + v14, 4 - v14);
        if ( v15 <= 0 )
          break;
        v14 += v15;
        if ( v14 > 3 )
        {
          v16 = 0;
          while ( 1 )
          {
            v17 = sub_41C290(v7, (char *)&v20 + v16, 8 - v16);
            if ( v17 <= 0 )
              goto LABEL_15;
            v16 += v17;
            if ( v16 > 7 )
              goto LABEL_9;
          }
        }
      }
    }
  }
LABEL_15:
  sub_41BEC0(v7);
  result = 0;
LABEL_4:
  if ( v23 != __readfsqword(0x28u) )
    sub_41D5A0();
  return result;
}
```

ida에서 `main` 함수를 찾을 수가 없어서 `Usage` 문자열이 존재하는 주소값을 기준으로 Jump to address를 수행해 주었다. `Usage` 는 `main` 함수 근처에서 쓰이기 때문에 해당 함수를 `main` 함수로 추정해볼 수 있다.

1. 소켓을 생성한다.
2. 포트 / ip주소를 파싱한다.
3. 서버에 연결 후, stage 길이 4bytes 읽고, stage 바이트를 수신한다.
4. 받은 코드를 함수처럼 호출한다.
5. 결과를 서버로 다시 보낸다.

대충 위와 같은 행동을 수행한다고 볼 수 있다. 따라서 해당 프로그램은 서버가 보낸 코드를 실행하는 게 주 역할이라고 볼 수 있다.

- `sub_41D470` -> `sys_socket`
- `sub_41D3D0` -> `sys_connect`
- `sub_401C40` -> `read_exact`
- `sub_41CC80` -> `sys_mmap`
- `sub_41CD70` -> `sys_munmap`
- `sub_41C290` -> `sys_write`

`syscall` 번호를 기준으로 확인해봤을 때, stripped된 함수명 중 일부는 위처럼 정리할 수 있을 거 같다.

```c
while (1) {
    read_exact(sock, &len, 4);
    buf = mmap(..., len, ...);
    read_exact(sock, buf, len);
    result = ((uint64_t (*)())buf)();
    munmap(buf, len);
    write(sock, &eight, 4);
    write(sock, &result, 8);
}
```

즉, 간단하게 위처럼 함수를 정리해줄 수 있다.

서버가 닫힌 관계로, 이후 분석은 미리 저장해 두었던 클라이언트의 stage 덤프 파일을 기준으로 진행하였다.

### stage 덤프 파일 구조

이후 등장하는 `raw.bin`, `decoded.bin` 파일들은 모두 분석 과정에서 서버가 보낸 stage를 로컬에 저장하면서 임의로 붙인 이름이다.

즉, 서버는 원래 이름 없는 바이트 덩어리를 stage 단위로 보내고, 이를 나중에 다시 분석하기 쉽도록 다음과 같은 규칙으로 저장하였다.

- `session_<label>_<idx>_raw.bin`
  - 서버에서 받은 원본 stage 바이트
- `session_<label>_<idx>_decoded.bin`
  - raw stage를 복호화한 실제 stage 코드

stage 파일을 바로 디스어셈블링해보면 실제 검사 코드가 바로 나타나지 않는다.

raw stage의 앞부분에는 짧은 복호화 코드가 붙어 있고, 뒤쪽에 암호화된 페이로드가 존재한다.

예를 들어 `live_stage_0.bin` 또는 `session_h3b_000_raw.bin`의 앞부분은 다음과 같은 형태를 가진다.

```bash
# objdump -D -b binary -mi386:x86-64 -M intel live_stage_0.bin | head -40

live_stage_0.bin:     file format binary

Disassembly of section .data:

0000000000000000 <.data>:
       0:       e8 00 00 00 00          call   0x5
       5:       5e                      pop    rsi
       6:       48 8d be 47 00 00 00    lea    rdi,[rsi+0x47]
       d:       b9 f7 8f 01 00          mov    ecx,0x18ff7
      12:       41 b2 45                mov    r10b,0x45
      15:       31 d2                   xor    edx,edx
      17:       44 30 14 17             xor    BYTE PTR [rdi+rdx*1],r10b
      1b:       ff c2                   inc    edx
      1d:       39 ca                   cmp    edx,ecx
      1f:       72 f6                   jb     0x17
      21:       31 d2                   xor    edx,edx
      23:       f6 14 17                not    BYTE PTR [rdi+rdx*1]
      26:       ff c2                   inc    edx
      28:       39 ca                   cmp    edx,ecx
      2a:       72 f7                   jb     0x23
      2c:       41 89 c8                mov    r8d,ecx
      2f:       41 ff c8                dec    r8d
      32:       31 d2                   xor    edx,edx
      34:       8a 04 17                mov    al,BYTE PTR [rdi+rdx*1]
      37:       8a 64 17 01             mov    ah,BYTE PTR [rdi+rdx*1+0x1]
      3b:       88 24 17                mov    BYTE PTR [rdi+rdx*1],ah
      3e:       88 44 17 01             mov    BYTE PTR [rdi+rdx*1+0x1],al
      42:       83 c2 02                add    edx,0x2
      45:       44 39 c2                cmp    edx,r8d
      48:       72 ea                   jb     0x34
      4a:       ff e7                   jmp    rdi
      4c:       ee                      out    dx,al
      4d:       fb                      sti
      4e:       ef                      out    dx,eax
      4f:       fb                      sti
      50:       ec                      in     al,dx
      51:       fb                      sti
      52:       ed                      in     eax,dx
```

위 코드는 대략 다음과 같은 순서로 동작한다.

1. 현재 코드 위치를 구한다.
2. payload 시작 위치와 길이를 계산한다.
3. XOR / NOT / swap 등의 방식으로 payload를 복호화한다.
4. 복호화가 끝나면 payload 시작 위치로 점프한다.

즉, raw stage는 실제 문제 로직이 아니라, 실제 문제 로직을 복호화해서 실행시키는 로더에 가깝다.

반대로 `*_decoded.bin`을 보면 실제 stage 로직을 확인할 수 있다.

`live_stage_0_decoded.bin`의 경우 `flag.png` 문자열이 바로 드러난다.

```bash
# strings -a live_stage_0_decoded.bin | head -20
ATAUAVAW1
flag.pngPH
A_A^A]A\
A_A^A]A\1
A_A^A]A\1
"il"
:vvD"
...
```

따라서 stage 분석은 항상 다음 순서를 따른다.

1. raw stage 확보
2. decoder 분석 및 payload 복호화
3. decoded stage 기준으로 동작 분류

### stage 복호화 방식

`decode_live_stages.py`를 보면 raw stage decoder는 크게 세 가지 패턴으로 분류할 수 있다.

- `xor-key8`
- `chain-add-xor`
- `xor-not-swap`

```python
def decode_stage(raw: bytes) -> tuple[bytes, str]:
    # call $+5; pop rsi; lea rdi, [rsi+disp]; mov ecx, len; ...
    if raw.startswith(b"\xe8\x00\x00\x00\x00\x5e\x48\x8d\xbe"):
        disp = u32(raw, 9)
        start = 5 + disp
        length = u32(raw, 14)
        p = bytearray(raw[start : start + length])
        rest = raw[18:start]

        # mov r10b, key; mov edx, 1; movzx eax, byte [rdi+rdx-1]; add [rdi+rdx], al; ...
        if rest.startswith(b"\x41\xb2") and b"\x00\x04\x17" in rest[:32]:
            key = rest[2]
            for i in range(1, len(p)):
                p[i] = (p[i] + p[i - 1]) & 0xFF
            for i in range(len(p)):
                p[i] ^= key
            return bytes(p), f"chain-add-xor disp=0x{disp:x} len=0x{length:x} key=0x{key:02x}"

        # mov r10b, key; xor edx, edx; xor [rdi+rdx], r10b; ... not [rdi+rdx]; ... swap pairs
        if rest.startswith(b"\x41\xb2") and b"\xf6\x14\x17" in rest and b"\x88\x24\x17" in rest:
            key = rest[2]
            for i in range(len(p)):
                p[i] ^= key
            for i in range(len(p)):
                p[i] = (~p[i]) & 0xFF
            for i in range(0, len(p) - 1, 2):
                p[i], p[i + 1] = p[i + 1], p[i]
            return bytes(p), f"xor-not-swap disp=0x{disp:x} len=0x{length:x} key=0x{key:02x}"

        raise ValueError(f"unknown call-pop-lea decoder rest={rest[:40].hex()}")

    # call $+5; pop rsi; movabs rax, key; push rax; lea rdi, [rsi+disp]; mov ecx, len; ...
    if raw.startswith(b"\xe8\x00\x00\x00\x00\x5e\x48\xb8"):
        key = raw[8:16]
        if raw[16:19] != b"\x50\x48\x8d" or raw[19] != 0xBE:
            raise ValueError("unknown movabs-key decoder")
        disp = u32(raw, 20)
        length = u32(raw, 25)
        start = 5 + disp
        p = bytearray(raw[start : start + length])
        for i in range(len(p)):
            p[i] ^= key[i & 7]
        return bytes(p), f"xor-key8 disp=0x{disp:x} len=0x{length:x} key={key.hex()}"

    return raw, "plain"
```

이 세 가지 패턴만 처리해도 대부분의 raw stage를 decoded stage로 복원할 수 있다.

`h3b` 세션의 115개 stage를 기준으로 보면, 복호화 방식 분포는 다음과 같았다.

- `xor-key8` : 55개
- `xor-not-swap` : 33개
- `chain-add-xor` : 27개

즉 raw stage의 겉모양은 다양하지만, 복호화 로직은 소수의 패턴으로 정리할 수 있었다.

### stage 분류

decoded stage를 문자열과 간단한 opcode 패턴 기준으로 분류하면, 전체 stage는 크게 다섯 종류로 나뉜다.

1. `flag.png` 검사 stage
2. 산수 문제 stage
3. ASCII-art 숫자 stage
4. `ptrace` anti-debug stage
5. 마지막 종료 stage

이 분류는 `solve_brain.py`의 `decide_return()`에서 자동화되어 있다.

```python
def decide_return(stage: bytes) -> tuple[int, str]:
    strings = printable_strings(stage)
    text = "\n".join(strings)

    m = re.search(r"Solve:\s*(.*?)\s*=\s*\?", text)
    if m:
        expr = m.group(1).strip()
        ans = eval_expr(expr)
        return ans, f"math {expr} = {ans}"

    for s in strings:
        art_num = parse_ascii_art_number(s)
        if art_num is not None:
            return art_num, f"ascii-art number = {art_num}"

    # ptrace(PTRACE_TRACEME, 0, 0, 0) anti-debug stage:
    # returns 0xdead0000 when not traced, 0xdead0001 otherwise.
    if b"\xb8\x65\x00\x00\x00\x0f\x05" in stage and b"\xad\xde" in stage:
        return 0xDEAD0000, "ptrace anti-debug -> 0xdead0000"

    # Normal large stages open flag.png and return 1 on success.
    if b"flag.png" in stage:
        return 1, "flag.png checker -> bypass success"

    if "Failed" in text:
        return 0, "failure stage received"

    if re.search(r"[A-Z0-9_{}]{6,}", text) or "flag" in text.lower():
        return 0, "interesting text: " + text.replace("\n", "\\n")[:200]

    return 1, "default 1"
```

기본 동작은 다음과 같다.

- decoded stage 안에 `flag.png`가 있으면 파일 검사 stage로 본다.
- `Solve:` 문자열이 있으면 산수 문제로 본다.
- `Input:`과 함께 ASCII art가 있으면 숫자 읽기 stage로 본다.
- `ptrace` 흔적이 있으면 anti-debug stage로 본다.
- `"All stages passed! Congratulations!"`가 있으면 종료 stage로 본다.

즉 이 문제는 stage를 완벽히 에뮬레이트하는 것이 아니라, stage가 요구하는 반환값이 무엇인지 판별해 직접 보내는 방식으로 해결할 수 있다.

### `h3b` 세션 기준 stage 순서

의미 있는 구간 단위로 정리하면 전체 흐름은 다음과 같다.

- `000 ~ 012` : `flag.png` 검사 stage
- `013` : ASCII-art 숫자 stage, 정답 `484557`
- `014 ~ 017` : `flag.png` 검사 stage
- `018` : ASCII-art 숫자 stage, 정답 `332076`
- `019 ~ 027` : `flag.png` 검사 stage
- `028` : ASCII-art 숫자 stage, 정답 `170955`
- `029 ~ 030` : `flag.png` 검사 stage
- `031` : ASCII-art 숫자 stage, 정답 `435516`
- `032 ~ 033` : `flag.png` 검사 stage
- `034` : 산수 stage, `(20 + 37) - 8 = 49`
- `035 ~ 041` : `flag.png` 검사 stage
- `042` : 산수 stage, `(27 + 18) + 2 = 47`
- `043 ~ 046` : `flag.png` 검사 stage
- `047` : ASCII-art 숫자 stage, 정답 `857377`
- `048 ~ 052` : `flag.png` 검사 stage
- `053` : 산수 stage, `(34 * 43) * 9 = 13158`
- `054` : `flag.png` 검사 stage
- `055` : ASCII-art 숫자 stage, 정답 `603159`
- `056` : `flag.png` 검사 stage
- `057` : ASCII-art 숫자 stage, 정답 `95537`
- `058 ~ 062` : `flag.png` 검사 stage
- `063` : 산수 stage, `(2 * 43) - 8 = 78`
- `064 ~ 065` : `flag.png` 검사 stage
- `066` : 산수 stage, `(4 + 24) - 4 = 24`
- `067 ~ 071` : `flag.png` 검사 stage
- `072` : 산수 stage, `(23 + 28) * 3 = 153`
- `073 ~ 080` : `flag.png` 검사 stage
- `081` : 산수 stage, `(44 - 21) * 6 = 138`
- `082` : ASCII-art 숫자 stage, 정답 `887364`
- `083 ~ 092` : `flag.png` 검사 stage
- `093` : `ptrace` anti-debug stage, 정답 `0xDEAD0000`
- `094 ~ 096` : `flag.png` 검사 stage
- `097` : 산수 stage, `(7 + 20) - 5 = 22`
- `098` : `flag.png` 검사 stage
- `099` : 산수 stage, `(48 + 13) - 7 = 54`
- `100 ~ 106` : `flag.png` 검사 stage
- `107` : 산수 stage, `(46 - 19) * 3 = 81`
- `108 ~ 113` : `flag.png` 검사 stage
- `114` : 마지막 종료 stage

이렇게 보면 stage 대부분은 `flag.png` 검사에 할당되어 있고, 중간중간 특수 stage가 섞여 있음을 알 수 있다.

### 특수 stage 예시

#### 1. `flag.png` 검사 stage

대부분의 stage는 `flag.png` 파일을 열고, 특정 오프셋의 데이터가 기대값과 일치하는지 검사하는 역할을 한다. 만약 조건이 맞으면 `1`, 아니면 `0`을 반환한다.

#### 2. 산수 stage

일부 stage는 간단한 산술식을 출력하고, 그 계산 결과를 반환값으로 요구한다. 이런 stage는 식만 파싱해서 계산하면 된다.

#### 3. ASCII-art 숫자 stage

일부 stage는 숫자를 ASCII-art 형태로 출력한 뒤, 사용자가 그 숫자를 그대로 입력하도록 한다. 이런 stage는 ASCII-art를 숫자 템플릿과 비교해 자동으로 읽어낼 수 있다.

#### 4. `ptrace` anti-debug stage

`session_h3b_093_decoded.bin`은 디버거 부착 여부를 검사하는 anti-debug stage이다. 이 stage는 traced 상태가 아닐 경우 `0xDEAD0000`을 반환하도록 되어 있다.

#### 5. 마지막 종료 stage

마지막 `session_h3b_114_decoded.bin`은 더 이상 문제를 내지 않고, `"All stages passed! Congratulations!"` 문자열을 출력한 뒤 종료한다.
### 자동화 방식

이 문제를 stage 하나씩 수동으로 읽어서 푸는 것은 사실상 비효율적이다.

총 115개의 stage 중 95개가 `flag.png` 검사 stage이기 때문에, 사람이 매번 직접 분석해서 반환값을 넣는 방식은 현실적이지 않다.

따라서 전체 풀이는 다음 두 단계로 자동화하였다.

1. 서버에서 받은 raw stage를 복호화한다.
2. decoded stage를 분류해서 그 stage가 요구하는 반환값을 직접 계산한다.

이 과정은 `solve_brain.py`에 정리되어 있다.

```python
def run(host: str, label: str | None = None, port: int = PORT) -> None:
    root = Path(__file__).resolve().parent
    prefix = label or host.replace(".", "_")
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(10)
        idx = 0
        while idx < 1000:
            hdr = recvall(sock, 4)
            if hdr is None:
                print("EOF")
                return
            size = struct.unpack("<I", hdr)[0]
            raw = recvall(sock, size)
            if raw is None:
                print("EOF while reading stage")
                return
            (root / f"session_{prefix}_{idx:03d}_raw.bin").write_bytes(raw)
            stage, infos = decode_recursive(raw)
            (root / f"session_{prefix}_{idx:03d}_decoded.bin").write_bytes(stage)
            value, why = decide_return(stage)
            strings = printable_strings(stage)
            preview = " | ".join(s.replace("\n", "\\n") for s in strings[:3])
            print(f"[{idx:02d}] raw={size} dec={len(stage)} {' -> '.join(infos)}")
            print(f"     {why}; strings={preview[:220]}")
            sock.sendall(struct.pack("<IQ", 8, value & 0xFFFFFFFFFFFFFFFF))
            idx += 1
        print("stage limit reached")

```

동작 순서는 다음과 같다.

1. 서버에서 `4bytes length + stage bytes`를 읽는다.
2. raw stage를 복호화해서 decoded stage를 만든다.
3. decoded stage 안의 문자열과 패턴을 보고 stage 종류를 판별한다.
4. 종류에 맞는 정답 값을 계산한다.
5. `uint32 8 + uint64 result` 형식으로 서버에 다시 전송한다.

즉, 이 문제는 stage 전체를 완벽히 에뮬레이트하는 것이 아니라, stage가 최종적으로 기대하는 반환값만 계산해서 직접 보내는 방식으로 해결할 수 있다.

### `flag.png` 검사 stage의 내부 구조

한편 `flag.png` 검사 stage는 모두 완전히 같은 형태는 아니었다.

decoded stage들을 분석해 보면, 내부 비교 방식은 대략 다음 다섯 가지 유형으로 나뉜다.

- `direct`
- `xor2`
- `xchain`
- `subchain`
- `dword`

이 분류는 `extract_flag_png.py`의 `extract_stage()`에서 처리한다.

[코드 삽입: `extract_flag_png.py`의 `extract_stage()` 핵심 부분]

각 유형의 의미를 간단히 정리하면 다음과 같다.

- `direct`
    - 파일 데이터와 내장 테이블을 직접 비교한다.
- `xor2`
    - stage 안의 두 테이블을 XOR한 결과와 비교한다.
- `xchain`
    - 첫 바이트 이후를 `prev ^ cur` 형태로 비교한다.
- `subchain`
    - 차분 형태의 테이블을 누적 복원해 비교한다.
- `dword`
    - 작은 4바이트 정수 값을 비교한다.

즉 95개의 `flag.png` 검사 stage는 단순히 같은 검사를 반복하는 것이 아니라, **서로 다른 오프셋과 서로 다른 비교 방식으로 `flag.png`의 여러 구간을 확인하는 stage 집합**이라고 볼 수 있다.

### 오프라인 `flag.png` 복원

`flag.png` 검사 stage는 온라인 bypass 관점에서는 단순히 `1`을 보내면 되지만, 내부적으로는 `flag.png`의 특정 오프셋과 기대값을 비교하는 데이터를 포함하고 있다.

이 데이터를 역으로 수집하면 `flag.png` 자체를 부분적으로 복원할 수 있다.

이를 위해 `extract_flag_png.py`를 사용해 decoded stage들에서 파일 오프셋과 비교 데이터를 추출하였다.

```python
...
session_h3b_110_decoded.bin              xor2     off=0x031e12 len=0x018f09 conflicts=0
session_h3b_112_decoded.bin              xchain   off=0x5bf700 len=0x018f08 conflicts=0
session_h3b_113_decoded.bin              xchain   off=0x71c970 len=0x018f08 conflicts=0
stage_3_38_146_7_0_decoded.bin           xchain   off=0x7cb2a8 len=0x018f08 conflicts=0
stage_54_180_255_106_0_decoded.bin       xchain   off=0x4ad1a8 len=0x018f08 conflicts=0

hits=506 skipped=290 covered=9091575/9193720 (98.89%) conflicts=0
wrote flag_partial.bin and flag_partial.mask
```

여러 세션에서 수집한 decoded stage를 모두 이용한 결과는 다음과 같다.

- `hits = 293`
- `skipped = 168`
- `covered = 9091575 / 9193720`
- `coverage = 98.89%`
- `conflicts = 0`

즉 전체 `flag.png` 파일의 약 98.89%를 충돌 없이 복원할 수 있었다.

복원 과정에서 생성된 주요 산출물은 다음과 같다.

- `flag_partial.bin`
- `flag_partial.mask`

### 최종 복원

복원된 `flag_partial.bin`만으로는 tail 영역 일부가 비어 있었기 때문에, 남은 영역을 시각적으로 확인하기 위해 `tail_image.png`를 확인하였다.

![tail_image](/image/2026-05-13/tail_image.png)

이미지의 tail 부분에서 최종 플래그를 읽을 수 있었다.



# 후기
솔직히 `Recover It!` 문제를 제외하고는 내 실력으로는 풀 수 없겠다 싶었다. AI 풀이를 어렵게 하기 위해 전체적으로 CTF 난이도가 근 2~3년 동안 엄청나게 수직상승한 거 같다. CTF 풀이를 위한 AI 세팅을 좀더 공부하는 게 좋을 거 같다.
`Brain Outside`도 롸업 쓰려고 보는데 내가 풀 수 있는 레벨은 전혀 아니었던 것 같다. AI를 막으려고 노력한게 느껴지는 문제였다.