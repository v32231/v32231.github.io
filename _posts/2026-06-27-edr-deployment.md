---
layout: post
title: "macOS에서 Elastic EDR 구축 및 탐지 분석"
date: 2026-06-27 23:36:00 +0900
categories: ["BD"]
tags: [security, edr, elastic, macos]
---

# Overview

## EDR

EDR(Endpoint Detection and Response)은 PC, 노트북, 서버와 같은 endpoint에서 발생하는 보안 이벤트를 지속적으로 수집하고, 위협을 탐지한 뒤 분석과 대응까지 수행하는 보안 체계이다. 여기서 endpoint란 사용자가 실제로 작업하거나 서비스가 실행되는 네트워크의 끝단 장치를 의미하며, 이번 실습에서는 macOS가 보호 대상 endpoint가 된다.

기존 백신이 이미 알려진 악성코드의 차단에 초점을 맞춘다면, EDR은 프로세스 실행, 파일 생성 및 변경, 네트워크 연결 등의 행위를 함께 기록한다. 따라서 단순히 악성 파일을 차단하는 것에서 끝나지 않고, 어떤 사용자가 어떤 프로세스를 실행했는지, 부모 프로세스는 무엇인지, 어떤 파일과 네트워크가 연관되었는지를 추적할 수 있다. 보안 담당자는 이 정보를 이용해 위협의 발생 원인과 범위를 조사하고 파일 격리, 프로세스 종료, 호스트 격리 등의 대응을 수행할 수 있다.

## Elastic

Elastic은 다양한 데이터를 수집, 저장, 검색하고 시각화하는 데이터 분석 플랫폼이다. 대표적으로 데이터를 저장하고 빠르게 검색하는 Elasticsearch와 데이터를 조회하고 시각화하는 Kibana를 제공한다. Elastic Security는 이러한 데이터 처리 기능을 보안 영역에 적용한 솔루션으로, SIEM과 EDR 기능을 한 화면에서 제공한다.

이번 EDR 환경은 다음 구성요소로 이루어진다.

- **Elastic Cloud**: Elastic Security를 실행하고 보안 데이터를 저장·분석하는 클라우드 환경
- **Elastic Security**: 보안 이벤트, 탐지 규칙, 탐지 경고 및 조사 기능을 제공
- **Elastic Agent**: endpoint에 설치되어 정책을 전달받고 시스템 및 보안 데이터를 Elastic Cloud로 전송하는 통합 에이전트
- **Elastic Defend**: 악성코드와 의심스러운 행위를 탐지·차단하고 endpoint telemetry 수집 범위를 정의하는 보안 기능
- **Elastic Endpoint**: Elastic Defend를 추가하면 endpoint에서 실제 탐지와 차단을 수행하는 보호 프로그램
- **Fleet**: Elastic Agent의 등록 상태, 버전 및 에이전트 정책을 중앙에서 관리하는 기능

## 실습 환경

| Endpoint OS | macOS 26.5.1 |
| --- | --- |
| CPU 아키텍처 | arm64 |
| Elastic Defend Integration | 9.4.0 |
| Agent | Elastic Agent 9.4.2 |

# Elastic EDR 구축

## **Elastic Cloud Security 프로젝트 생성**

Elastic EDR 환경을 구축하기 위해 먼저 Elastic Cloud에 로그인한 뒤, Serverless Security 프로젝트를 생성했다. 클라우드 제공자는 Google Cloud를 선택했고, 데이터 저장 리전은 `US Central 1 (Iowa)`로 설정했다. 클라우드 제공자와 리전은 실습 환경에 따라 다르게 선택해도 된다.

## Elastic Defend 추가

![Elastic Defend Complete EDR 설정](/image/2026-06-27/0628_edr1.png)

Elastic Defend의 이름은 `mac-edr-defend`로 설정했다. 보호 대상은 데스크톱과 노트북에 해당하는 `Traditional Endpoints`를 선택했으며, 파일과 네트워크를 포함한 전체 telemetry를 수집하기 위해 `Complete EDR`을 적용했다.

## 에이전트 정책 생성

![mac-edr-policy 생성](/image/2026-06-27/0628_edr2.png)

Elastic Defend 설정을 적용할 새로운 에이전트 정책을 생성했다. 시스템 로그와 성능 지표도 함께 수집하도록 `Collect system logs and metrics` 항목을 활성화했다.

![Elastic Defend 추가 완료](/image/2026-06-27/0628_edr3.png)

설정을 저장한 뒤 Elastic Defend의 Integration policies 화면에서 `mac-edr-defend`가 생성되고 에이전트 정책에 연결된 것을 확인할 수 있다.

## **Elastic Agent 설치 및 등록**

```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.4.2-darwin-aarch64.tar.gz
tar xzvf elastic-agent-9.4.2-darwin-aarch64.tar.gz
cd elastic-agent-9.4.2-darwin-aarch64

sudo ./elastic-agent install \
  --url="https://<FLEET_SERVER_HOST>:443" \
  --enrollment-token="<ENROLLMENT_TOKEN>"
```

Fleet의 Agents 메뉴에서 macOS용 설치 명령을 확인하고 터미널에서 관리자 권한으로 실행했다. 설치가 완료되면 `Elastic Agent has been successfully installed.`라는 성공 메시지가 출력된다.

## macOS 보안 권한 설정

macOS에서 Elastic Endpoint가 정상적으로 시스템 활동을 감시하려면 다음 권한을 허용해야 한다.

- Endpoint Security 시스템 확장 기능
- 네트워크 콘텐츠 필터링
- 전체 디스크 접근 권한

![Fleet Agent Healthy 상태](/image/2026-06-27/0628_edr4.png)

권한 설정을 마친 뒤 Fleet에서 Agent 상태를 확인해보면 호스트가 `mac-edr-policy`에 등록되었으며 상태가 `Healthy`로 표시되었다. 이걸 통해 Elastic Agent가 Elastic Cloud와 정상적으로 통신하고 정책을 적용받는다는 것을 확인할 수 있다.

## **EDR 탐지 테스트**

실습은 실제 악성코드 대신 EICAR 테스트 파일을 사용했다.

```bash
cd ~/Downloads
curl -O https://secure.eicar.org/eicar.com.txt
```

EICAR 테스트 파일은 위 명령어를 통해 다운 받았다. 명령 실행 결과 68bytes의 테스트 파일이 다운로드되었으며 이후 파일이 다운로드 경로에서 즉시 사라졌으며, Elastic Defend가 해당 파일을 탐지하고 차단한 것을 확인했다.

![Malware Prevention Alert 상세 화면](/image/2026-06-27/0628_edr5.png)

Elastic Security의 Alerts 메뉴를 확인한 결과 `Malware Prevention Alert`가 2건 생성되었다. 두 경고 모두 심각도는 `High`, 위험 점수는 73으로 표시되었다. 탐지 경고의 상세 화면에서 다음 정보를 확인할 수 있다.

| 분석 항목 | 확인 결과 |
| --- | --- |
| 탐지 시각 | 2026-06-27 23:36:30 |
| 탐지명 | `Malware Prevention Alert` |
| 심각도 | `High` |
| 위험 점수 | 73 |
| 상태 | `Open` |
| 호스트 | `bagdahyeon-ui-macbookpro.local` |
| 사용자 | `bagdahyeon` |
| 탐지 파일 | `eicar.com.txt` |
| 실행 프로세스 | `curl` |
| 부모 프로세스 | `zsh` |
| 탐지 건수 | 2건 |

Alert reason에는 `zsh`의 하위 프로세스로 실행된 `curl`이 `eicar.com.txt` 파일을 생성한 흐름이 기록되어 있었다.

```text
zsh
 └─ curl
     └─ eicar.com.txt 생성
         └─ Elastic Defend 탐지 및 차단
```

다운로드된 파일이 원래 경로에서 즉시 사라진 것으로 보아 Complete EDR의 Prevent 설정에 따라 파일이 차단 및 격리된 것으로 보인다.

```bash
cd ~/Downloads
curl -O https://secure.eicar.org/eicar.com.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    68  100    68    0     0     55      0  0:00:01  0:00:01 --:--:--    55
```
