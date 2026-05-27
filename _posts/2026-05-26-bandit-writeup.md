---
layout: post
title: "bandit 풀이"
date: 2026-05-26 09:00:00 +0900
categories: ["BD"]
tags: [blog, techdocs, wsl]
---

bandit wargame은 워게임에 필수적인 기본 사항들을 게임처럼 연습할 수 있는 서비스이다.
참고로 나는 3년 전인가 한 12>13 단계까지 풀어봤던 기억이 있다. 이 블로그 글에서는 24>25 단계까지 풀이를 정리할 예정이다.
참고로 그 전 단계에 나온 리눅스 명령어들에 대한 설명은 생략하겠다.

# 0
![bandit](/image/2026-05-26/bandit.png)
bandit 사이트에 나와있는 설명대로 ssh 연결을 해서 bandit wargame 서버에 접속할 수 있다.

비밀번호는 ‘bandit0’을 입력해주면 된다.

# 0>1
![bandit](/image/2026-05-26/bandit0.png)

1. `ls` 명령어를 사용하여 현재 디렉토리의 파일을 전부 확인했더니 ‘readme’ 라는 파일을 발견했다.
2. `cat` 명령어를 사용하여 ‘readme’ 파일을 읽었다.

# 1>2
![bandit](/image/2026-05-26/bandit1.png)

1. `ls`  명령어를 사용하여 내부 파일들을 확인한다.
2. `cat` 명령어를 사용하여 ‘-’ 라는 디렉토리를 읽었다. 참고로 `cat -` 이렇게만 입력하면 ‘-’가 파일 이름이 아니라 ‘키보드 입력’으로 인식되기 때문에 ‘./-’ 이렇게 경로로 입력해주어야 한다.

# 2>3
![bandit](/image/2026-05-26/bandit2.png)

1. `ls`  명령어를 사용하여 내부 파일들을 확인한다.
2. `cat` 명령어를 사용하여 ‘--spaces in this filename—’ 라는 디렉토리를 읽었다. 참고로 파일명에 띄워쓰기가 포함되어 있는 경우엔 따옴표를 사용해서 입력해주어야 한다.

# 3>4
![bandit](/image/2026-05-26/bandit3.png)

1. `ls` 명령어를 사용하여 ‘inhere’ 이라는 디렉토리가 존재하는 걸 확인한다.
2. `cd` 명령어를 사용하여 ‘inhere’ 디렉토리로 이동한다.
3. `ls -a` 명령어를 사용하여 해당 디렉토리의 숨김 파일을 확인한다.
4. `cat` 명령어를 사용하여 ‘...Hiding-From-You’ 파일의 내용을 확인한다.

# 4>5
![bandit](/image/2026-05-26/bandit4.png)

1. `ls` 명령어를 사용하여 ‘inhere’ 이라는 디렉토리가 존재하는 걸 확인한다.
2. `cd` 명령어를 사용하여 ‘inhere’ 디렉토리로 이동한다.
3. 문제 설명에 유일하게 읽을 수 있는 파일에 비밀번호가 저장되어 있다고 해서 `cat` 명령어로 하나씩 확인한 결과 ‘-file07’ 파일에서 찾을 수 있었다.

위와 같이 풀기는 하였으나 해당 풀이가 제작자가 의도한 풀이는 아닌 거 같아서 인터넷에 검색해 봤다. 검색 결과, `file ./-file0*` 라는 명령어를 사용하면 간단하게 풀 수 있는 문제였다. `file` 은 파일 정보를 출력해주는 명령어이고, ‘*'는 아무 글자라는 뜻이다. 즉, ‘./-file0*’는 이름이 ‘-file0’으로 시작하고 뒤에 뭐가 더 붙어도 되는 파일들을 의미한다. 어차피 디렉토리 안에 있는 파일을 모두 확인해야 하니 `file ./*` 까지만 적어도 똑같이 작동한다.
![bandit](/image/2026-05-26/bandit4_2.png)

# 5>6
![bandit](/image/2026-05-26/bandit5.png)

1. `ls` 명령어를 사용하여 ‘inhere’ 이라는 디렉토리가 존재하는 걸 확인했다.
2. `cd` 명령어를 사용하여 ‘inhere’ 디렉토리로 이동한다.
3. 문제에서 크기는 1033bytes 라고 했기 때문에 `find . -wholename "./maybehere0*/.file*" -size 1033c` 명령어를 사용해준다. `find` 명령어는 파일을 검색하는 데에 사용하는 명령어이고, ‘-wholename’ 옵션은 전체 경로가 지정한 패턴과 일치하는 파일로 특정지어주고, ‘-size’는 파일의 크기를 특정 지을 수 있다. 즉, 해당 명령어는 현재 디렉토리 아래에서, 경로가 특정 패턴과 맞고 크기가 정확히 1033bytes인 파일을 찾아달라는 뜻이다.

# 6>7
![bandit](/image/2026-05-26/bandit6.png)

1. 홈 디렉토리에 있는 파일 말고도 해당 서버에 존재한다고 되어 있기 때문에 `find` 명령어로 조건에 맞는 파일을 추린다. `find / -size 33c -type f -user bandit7 -group bandit6 2>&1` 라는 명령어를 사용했으며 `-type f` 는 일반 파일로 제한하겠다는 옵션이고(디렉토리, 심볼릭 링크 제외), `-user bandit7 -group bandit6` 은 유저 소유자가 ‘bandit7’이고, 그룹 소유자가 ‘bandit6’인 파일로 제한하겠다는 옵션이다. `2>&1` 은 표준 에러(stderr)를 표준 출력(stdout)으로 합친다는 뜻이다. 접근 거부 에러를 이후에 `grep` 명령어로 잡아내기 위한 옵션이다.
2. `find` 명령어로 추린 파일들에서 권한으로 인한 접근 거부가 일어나지 않는 파일을 찾아야 하기 때문에 파이프라인(|)을 사용해서 표준 출력 결과를 다음 명령어로 넘긴다.
3. `grep` 파이프라인을 통해 넘어온 표준 출력 결과에서 접근 거부 에러가 나지 않은 파일을 찾는다. `-v "Permission denied"` 는 ‘Permission denied’ 라는 문자열을 제외한 결과를 출력해 달라는 의미이다.
4. `cat` 명령어를 사용하여 ‘/var/lib/dpkg/info/bandit7.password’ 파일의 내용을 확인한다.

### 파일 디스크립터

| 번호 | 의미 |
| --- | --- |
| 0 | 표준 입력(Standard input) |
| 1 | 표준 출력(Standard output) |
| 2 | 표준 에러(Standard error) |

### 리다이렉션

| 명령어 | 의미 |
| --- | --- |
| `command > file` | 정상 출력을 파일에 저장, 덮어쓰기 |
| `command >> file` | 정상 출력을 파일에 추가 |
| `command 2> file` | 에러 출력을 파일에 저장 |
| `command 2> /dev/null` | 에러 메시지 숨기기 |
| `command > file 2>&1` | 정상 출력과 에러를 모두 파일에 저장 |
| `command &> file` | 정상 출력과 에러를 모두 파일에 저장 |
| `command < file` | 파일을 입력으로 사용 |

# 7>8
![bandit](/image/2026-05-26/bandit7.png)

1. `ls` 명령어를 사용해서 ‘data.txt’ 파일이 현재 디렉토리에 있는 것을 확인한다.
2. `grep 'millionth' ./data.txt` 명령어를 사용해서 'millionth' 문자열이 존재하는 줄을 출력한다.

# 8>9
![bandit](/image/2026-05-26/bandit8.png)

1. `sort data.txt` 명령어를 사용해서 ‘data.txt’ 파일에 있는 문자열을 한 줄로 정리한다.
2. 해당 결과를 `uniq -c` 명령어를 사용하면 중복된 줄을 하나로 합치고, 앞에 몇 번 등장했는지 개수를 붙여준다.
3. 해당 결과에서 `grep "1 “` 명령어로 한 번 등장한 문자열을 출력한다.

# 9>10
![bandit](/image/2026-05-26/bandit9.png)

1. `strings data.txt` 명령어를 사용해서 출력 가능한 문자열(사람이 읽을 수 있는 문자열)을 뽑는다.
2. 해당 결과에 `grep "=="` 명령어를 써서 ‘==’를 포함하는 모든 줄을 출력한다.

# 10>11
![bandit](/image/2026-05-26/bandit10.png)

1. `base64 -d ./data.txt` 명령어를 사용해서 data.txt에 있는 문자열을 base64 디코딩한 결과를 출력한다.

# 11>12
![bandit](/image/2026-05-26/bandit11.png)

1. `cat` 명령어로 파일 내용을 출력한다.
2. 모든 소문자, 대문자가 13자리씩 회정되어 있다고 했기 때문에 해당 결과에서 `tr 'A-Za-z' 'N-ZA-Mn-za-m'` 명령어로 회전시킨다. `tr` 명령어는 문자를 다른 문자로 치환시키는 명령어이고, `'A-Za-z' 'N-ZA-Mn-za-m'` 는 A-Z를 N-ZA-M으로, a-z를 n-za-m으로 치환시키겠다는 의미이다.

# 12>13
![bandit](/image/2026-05-26/bandit12.png)

이 단계는 `file` 로 파일 정보 확인 후, 압축 해제만 반복해주면 되는 문제이다. 사용한 명령어는 다음과 같다.

| 압축 방식 | 압축 해제 명령어 | 설명 |
| --- | --- | --- |
| `gzip` | `gunzip 파일명.gz` | `.gz` 파일을 압축 해제할 때 사용. 압축을 풀면 `.gz`가 제거된 파일이 생성됨 |
|  | `gzip -d 파일명.gz` | `gunzip`과 같은 의미. `-d`는 decompress, 압축 해제 |
| `bzip2` | `bunzip2 파일명.bz2` | `.bz2` 파일을 압축 해제할 때 사용. 압축을 풀면 `.bz2`가 제거된 파일이 생성됨 |
|  | `bzip2 -d 파일명.bz2` | `bunzip2`와 같은 의미. `-d`는 압축 해제 |
| `tar` | `tar -xf 파일명.tar` | `.tar` 아카이브를 풀 때 사용. `tar`는 압축이라기보다 여러 파일을 하나로 묶은 것에 가까움 |

참고로 `xxd -r data.txt data` 명령어는 ‘data.txt’에 들어 있는 16진수 덤프를 원래 바이너리 파일로 복원해서 ‘data’ 파일로 저장하는 명령어이다.

# 13>14
![bandit](/image/2026-05-26/bandit13.png)

1. `scp` 명령어를 사용해서 서버에 있는 파일을 로컬로 복사한다. `scp -P 2220 bandit13@bandit.labs.overthewire.org:sshkey.private .` 는 Bandit 서버에 있는 ‘sshkey.private’ 파일을 내 현재 로컬 폴더로 복사하는 명령어이다.
2. 그냥은 권한이 없기 때문에 `chmod` 명령어로 읽기 권한을 부여해준다. ‘400’이면 소유주에게 읽기 권한을 주겠다는 의미이다.
3. `-i` 옵션을 사용해서 ‘sshkey.private’ 파일을 세션키로 지정해서 bandit 14단계로 ssh 접속을 한다.

# 14>15
![bandit](/image/2026-05-26/bandit14.png)

1. `cat` 명령어로 ‘/etc/bandit_pass/bandit14’에 있는 세션키를 읽는다.
2. 해당 결과를 `nc localhost 30000` 명령어로 localhost 30000 포트로 보낸다.

# 15>16
![bandit](/image/2026-05-26/bandit15.png)
![bandit](/image/2026-05-26/bandit15_2.png)

1. `cat` 명령어로 ‘/etc/bandit_pass/bandit15’ 파일의 내용을 확인한다.
2. `openssl s_client` 명령어로 SSL/TLS 연결을 만들어 서버와 통신하는 명령어로 지정한 서버와 데이터를 주고받는다. `-connect localhost:30001`현재 서버의 `30001`번 포트를 지정해준다.
3. ‘/etc/bandit_pass/bandit15’ 파일의 내용인 ‘kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx’를 보낸다.

# 16>17
![bandit](/image/2026-05-26/bandit16.png)
![bandit](/image/2026-05-26/bandit16_2.png)

1. localhost 31000~32000 사이의 포트번호로 전송해야 하기 때문에 `nmap -Pn --open -p 31000-32000 localhost` 명령어를 사용한다. `nmap` 은 포트를 스캔할 때 사용하는 명령어이고, `-Pn` 은 핑 검사를 생략하라는 옵션, `--open` 은 열린 포트만 출력하라는 옵션, `-p 31000-32000` 는 해당 범위만 검사하라는 옵션이다.
2. `openssl s_client -connect localhost:31790 -quiet` 명령어로 31790 포트에 SSL/TLS 클라이언트로 직접 접속한다. 다른 포트들은 입력 값을 그대로 출력하거나 SSL 포트가 아니었다.
3. 이전 비밀번호를 입력하면 프라이빗 키를 얻을 수 있는데 `vim` 명령어로 파일을 하나 만들어 저장한다. `vim` 명령어는 일종의 편집기이다.
4. 해당 파일을 그냥 사용하면 안전하지 않은 파일로 인식되어 접속이 막힌다. 따라서 `chmod` 로 권한 설정 후 들어간다.

# 17>18
![bandit](/image/2026-05-26/bandit17.png)

1. `ls`  명령어를 사용하여 내부 파일들을 확인하면 ‘passwords.new’, ‘passwords.old’ 파일들을 볼 수 있다.
2. `diff` 명령어를 사용하여 해당 파일들의 다른 부분을 비교하여 출력한다. (바이너리 디핑하는 명령어라고 보면 된다.)

# 18>19
![bandit](/image/2026-05-26/bandit18.png)

1. 처음 ssh로 접속할때 그냥 `cat readme` 명령어를 인자로 넘겨버린다.

# 19>20
![bandit](/image/2026-05-26/bandit19.png)

1. 비밀번호를 얻으려면 `cat /etc/bandit_pass/bandit20` 명령어를 실행해야 하는데 권한 부족으로 그냥은 실행시킬 수 없다.
2. `./bandit20-do cat /etc/bandit_pass/bandit20` 이런 식으로 사용하면 ‘bandit20-do’ 파일의 권한으로 명령어를 실행할 수 있다.

# 20>21
![bandit](/image/2026-05-26/bandit20.png)
![bandit](/image/2026-05-26/bandit20_2.png)

1. 먼저 서버 역할을 하는 터미널을 설정한다. `-lp 31337`  옵션을 써서 31337 포트를 지정해서 listen 모드로 기다린다.
2. ‘/etc/bandit_pass/bandit20’ 파일을 표준 입력으로 넣어서 31337 포트에 접속한 상대에게 해당 파일 내용을 전달한다.
3. 서버 역할 터미널에 이전 단계 비밀번호를 입력한다.
4. 새 터미널을 열고, 클라이언트 역할 터미널은 `./suconnect 31337` 명령어를 사용해서 'sunconnect' 프로그램을 통해 포트를 연다.
5. 서버 역할 터미널에 비밀번호가 출력된다.

# 21>22
![bandit](/image/2026-05-26/bandit21.png)

1. ‘cronjob_bandit22’ 파일을 읽는다. `@reboot` 는 재부팅 시 실행시킨다는 의미이고, `* * * * *` 는 매분 마다 실행시킨다는 의미, `bandit22 /usr/bin/cronjob_bandit22.sh` 는 ‘bandit22 소유주의 권한으로 ‘cronjob_bandit22.sh’를 실행시키겠다는 뜻이다.
2. 따라서 ‘cronjob_bandit22.sh’ 파일의 내용을 확인하면 ‘/tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv’ 파일을 다른 사용자도 읽을 수 있게 권한을 바꾸는 명령어이다.
3. `cat` 명령어로 해당 파일을 읽는다.

# 22>23
![bandit](/image/2026-05-26/bandit22.png)

1. ‘cronjob_bandit23’ 파일을 읽으면 bandit23 소유주의 권한으로 ‘/usr/bin/cronjob_bandit23.sh’를 실행한다.
2. 따라서 ‘cronjob_bandit22.sh’ 파일의 내용을 확인하면 `mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)` 이런 명령어를 사용하는 걸 알 수 있다. 위에서 소유주가 ‘bandit23’이라고 나왔기 때문에 `echo I am user bandit23 | md5sum` 명령어로 MD5 해시값을 계산한다.
3. 우리가 알고 싶은 건 ‘/etc/bandit_pass/bandit23’의 내용이니까 `cat /etc/bandit_pass/$myname > /tmp/$mytarget` 명령어에 맞춰서 `cat /tmp/8ca319486bfbbc3663ea0fbe81326349` 로 해당 파일을 확인한다.

# 23>24
![bandit](/image/2026-05-26/bandit23.png)
![bandit](/image/2026-05-26/bandit23_2.png)

1. `/etc/cron.d/cronjob_bandit24` 파일을 읽는다.
2. `/usr/bin/cronjob_bandit24.sh` 파일의 내용을 확인한다.
3. `/tmp` 아래에 작업 디렉토리를 만든다. `mktemp -d`로 만든 디렉토리는 기본적으로 현재 사용자만 접근할 수 있기 때문에, bandit24가 결과 파일을 쓸 수 있도록 권한을 열어준다.
4. `vim` 으로 파일을 만들어서 bandit24 비밀번호를 복사하는 스크립트를 만든다. 내용은 다음과 같다.
    
    ```bash
    #!/bin/bash
    cat /etc/bandit_pass/bandit24 > /tmp/tmp.XAH6ylcawu/pass
    chmod 644 /tmp/tmp.XAH6ylcawu/pass
    ```
    
5. 만든 스크립트에 실행 권한을 주고, cron이 실행하는 디렉토리로 복사한다.
6. cron은 매 분마다 실행되므로 잠시 기다린 뒤, 결과 파일을 확인한다.

# 24>25
![bandit](/image/2026-05-26/bandit24.png)
![bandit](/image/2026-05-26/bandit24_2.png)

1. 비밀번호를 얻으려면 현재 단계의 비밀번호와 4자리 PIN 코드를 localhost의 30002 포트로 보내야 한다. 따라서 ‘cat /etc/bandit_pass/bandit24’ 파일을 읽어서 현재 단계의 비밀번호를 읽는다.
2. 어차피 0000~9999 사이의 숫자일 거기 때문에 임시 디렉토리를 생성해서 브루트 포싱을 할 파일을 만든다. 내용은 다음과 같다.
    
    ```bash
    #!/bin/bash
    
    password="gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8"
    
    for pin in $(seq -w 0000 9999)
    do
        echo "$password $pin"
    done | nc localhost 30002
    ```
    
3. 해당 파일에 실행 권한을 주고, 실행시키면 된다.