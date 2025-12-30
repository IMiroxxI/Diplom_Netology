## 2.0 Выполнение дипломной работы.
### 2.1 Заполнение конфигурационного файла terraform `main.tf` для выполнения задач дипломной работы.
Ссылки на файлы terraform

[main.tf](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20terraform/main.tf)

[meta.yaml](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20terraform/meta.yaml)

[.terraformrc](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20terraform/terraformrc)

#### По условиям задачи необходимо развернуть через terraform следующий ресурcы:

##### Сайт. Веб-сервера. Nginx.
- Создать две ВМ в разных зонах, установить на них сервер nginx.
- Создать Target Group, включить в неё две созданные ВМ.
- Создать Backend Group, настроить backends на target group, ранее созданную. Настроить healthcheck на корень (/) и порт 80, протокол HTTP.
- Создать HTTP router. Путь указать — /, backend group — созданную ранее.
- Создать Application load balancer для распределения трафика на веб-сервера, созданные ранее. Указать HTTP router, созданный ранее, задать listener тип auto, порт 80.

```terraform
## Nginx-web-1
resource "yandex_compute_instance" "nginx-web-1" {
  name        = "nginx-web-1"
  hostname    = "nginx-web-1"
  zone        = "ru-central1-a"  # ПРОСТОЕ ЗНАЧЕНИЕ
  platform_id = "standard-v3"
  
  resources {
    cores         = 2
    core_fraction = 20
    memory        = 2
  }

  boot_disk {
    initialize_params {
      image_id = data.yandex_compute_image.ubuntu.id
      size     = 10
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.a-subnet-diplom.id
    ipv4      = true
    ip_address = "192.168.10.3"
    security_group_ids = [
      yandex_vpc_security_group.bastion-security-local.id,
      yandex_vpc_security_group.nginx-web-security.id,
      yandex_vpc_security_group.filebeat-security.id
    ]
  }

  metadata = {
    ssh-keys = "ubuntu:${file("/home/alex/.ssh/id_ed25519.pub")}"
  }
}

## Nginx-web-2
resource "yandex_compute_instance" "nginx-web-2" {
  name        = "nginx-web-2"
  hostname    = "nginx-web-2"
  zone        = "ru-central1-b"  # ПРОСТОЕ ЗНАЧЕНИЕ
  platform_id = "standard-v3"
  
  resources {
    cores         = 2
    core_fraction = 20
    memory        = 2
  }

  boot_disk {
    initialize_params {
      image_id = data.yandex_compute_image.ubuntu.id
      size     = 10
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.b-subnet-diplom.id
    ipv4      = true
    ip_address = "192.168.20.3"
    security_group_ids = [
      yandex_vpc_security_group.bastion-security-local.id,
      yandex_vpc_security_group.nginx-web-security.id,
      yandex_vpc_security_group.filebeat-security.id
    ]
  }

  metadata = {
    ssh-keys = "ubuntu:${file("/home/alex/.ssh/id_ed25519.pub")}"
  }
}

## Target group
resource "yandex_alb_target_group" "nginx-target-group" {
  name = "nginx-target-group"

  target {
    subnet_id   = yandex_vpc_subnet.a-subnet-diplom.id
    ip_address  = yandex_compute_instance.nginx-web-1.network_interface.0.ip_address
  }

  target {
    subnet_id   = yandex_vpc_subnet.b-subnet-diplom.id
    ip_address  = yandex_compute_instance.nginx-web-2.network_interface.0.ip_address
  }
}

## Backend group
resource "yandex_alb_backend_group" "nginx-backend-group" {
  name = "nginx-backend-group"
  
  session_affinity {
    connection {
      source_ip = false
    }
  }

  http_backend {
    name             = "http-backend"
    weight           = 1
    port             = 80
    target_group_ids = [yandex_alb_target_group.nginx-target-group.id]
    
    load_balancing_config {
      panic_threshold = 90
    }
    
    healthcheck {
      timeout             = "10s"
      interval            = "2s"
      healthy_threshold   = 10
      unhealthy_threshold = 15
      
      http_healthcheck {
        path = "/"
      }
    }
  }
}

## HTTP router
resource "yandex_alb_http_router" "nginx-tf-router" {
  name   = "nginx-tf-router"
  labels = {
    tf-label    = "tf-label-value"
    empty-label = ""
  }
}

resource "yandex_alb_virtual_host" "nginx-virtual-host" {
  name           = "nginx-virtual-host"
  http_router_id = yandex_alb_http_router.nginx-tf-router.id
  
  route {
    name = "nginx-route"
    
    http_route {
      http_route_action {
        backend_group_id = yandex_alb_backend_group.nginx-backend-group.id
        timeout          = "60s"
      }
    }
  }
}

## Application load balancer
resource "yandex_alb_load_balancer" "nginx-balancer" {
  name       = "nginx-balancer"
  network_id = yandex_vpc_network.network-diplom.id

  allocation_policy {
    location {
      zone_id   = "ru-central1-d"  # ПРОСТОЕ ЗНАЧЕНИЕ
      subnet_id = yandex_vpc_subnet.d-subnet-diplom.id
    }
  }

  listener {
    name = "nginx-listener"
    
    endpoint {
      address {
        external_ipv4_address {}
      }
      ports = [80]
    }
    
    http {
      handler {
        http_router_id = yandex_alb_http_router.nginx-tf-router.id
      }
    }
  }
}
```
##### Мониторинг. Zabbix. Zabbix-agent.
- Создать ВМ, развернуть на ней Zabbix. На каждую ВМ установить Zabbix Agent, настроить агенты на отправление метрик в Zabbix.
```terrarom
## Zabbix
resource "yandex_compute_instance" "zabbix" {
  name        = "zabbix"
  hostname    = "zabbix"
  zone        = "ru-central1-d"  # ПРОСТОЕ ЗНАЧЕНИЕ
  platform_id = "standard-v3"
  
  resources {
    cores         = 2
    core_fraction = 20
    memory        = 2
  }

  boot_disk {
    initialize_params {
      image_id = data.yandex_compute_image.ubuntu.id
      size     = 20
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.d-subnet-diplom.id
    nat       = true
    ipv4      = true
    ip_address = "192.168.30.4"
    security_group_ids = [
      yandex_vpc_security_group.bastion-security-local.id,
      yandex_vpc_security_group.zabbix-security.id
    ]
  }

  metadata = {
    ssh-keys = "ubuntu:${file("/home/alex/.ssh/id_ed25519.pub")}"
  }
}
```
##### Логи. Elasticsearch. Kibana. Filebeat.
```terraform
## Elasticsearch
resource "yandex_compute_instance" "elasticsearch" {
  name        = "elasticsearch"
  hostname    = "elasticsearch"
  zone        = "ru-central1-a"  # ПРОСТОЕ ЗНАЧЕНИЕ
  platform_id = "standard-v3"
  
  resources {
    cores         = 2
    core_fraction = 20
    memory        = 4
  }

  boot_disk {
    initialize_params {
      image_id = data.yandex_compute_image.ubuntu.id
      size     = 20
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.a-subnet-diplom.id
    ipv4      = true
    ip_address = "192.168.10.4"
    security_group_ids = [
      yandex_vpc_security_group.bastion-security-local.id,
      yandex_vpc_security_group.elasticsearch-security.id,
      yandex_vpc_security_group.kibana-security.id,
      yandex_vpc_security_group.filebeat-security.id
    ]
  }

  metadata = {
    ssh-keys = "ubuntu:${file("/home/alex/.ssh/id_ed25519.pub")}"
  }
}

## Kibana
resource "yandex_compute_instance" "kibana" {
  name        = "kibana"
  hostname    = "kibana"
  zone        = "ru-central1-d"  # ПРОСТОЕ ЗНАЧЕНИЕ
  platform_id = "standard-v3"
  
  resources {
    cores         = 2
    core_fraction = 20
    memory        = 2
  }

  boot_disk {
    initialize_params {
      image_id = data.yandex_compute_image.ubuntu.id
      size     = 10
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.d-subnet-diplom.id
    nat       = true
    ipv4      = true
    ip_address = "192.168.30.5"
    security_group_ids = [
      yandex_vpc_security_group.bastion-security-local.id,
      yandex_vpc_security_group.elasticsearch-security.id,
      yandex_vpc_security_group.kibana-security.id,
      yandex_vpc_security_group.filebeat-security.id
    ]
  }

  metadata = {
    ssh-keys = "ubuntu:${file("/home/alex/.ssh/id_ed25519.pub")}"
  }
}
```
##### Сеть.
- Развернуть один VPC.
- Сервера web, Elasticsearch поместить в приватные подсети. 
- Сервера Zabbix, Kibana, application load balancer определить в публичную подсеть.
- Настроить Security Groups соответствующих сервисов на входящий трафик только к нужным портам.
- Настроить ВМ с публичным адресом, в которой будет открыт только один порт — ssh. Эта вм будет реализовывать концепцию bastion host.
```terraform
## Network https://cloud.yandex.ru/ru/docs/vpc/operations/network-create
resource "yandex_vpc_network" "network-diplom" {
  name        = "network-diplom"
  description = "Network diplom"
}

## Subnet. Gateway. Route table
resource "yandex_vpc_subnet" "a-subnet-diplom" {
  name           = "a-subnet-diplom"
  v4_cidr_blocks = ["192.168.10.0/24"]
  zone           = "ru-central1-a"  # ПРОСТОЕ ЗНАЧЕНИЕ
  network_id     = yandex_vpc_network.network-diplom.id
  route_table_id = yandex_vpc_route_table.a-b-subnet-route-table.id
}

resource "yandex_vpc_subnet" "b-subnet-diplom" {
  name           = "b-subnet-diplom"
  v4_cidr_blocks = ["192.168.20.0/24"]
  zone           = "ru-central1-b"  # ПРОСТОЕ ЗНАЧЕНИЕ
  network_id     = yandex_vpc_network.network-diplom.id
  route_table_id = yandex_vpc_route_table.a-b-subnet-route-table.id
}

resource "yandex_vpc_subnet" "d-subnet-diplom" {
  name           = "d-subnet-diplom"
  v4_cidr_blocks = ["192.168.30.0/24"]
  zone           = "ru-central1-d"  # ПРОСТОЕ ЗНАЧЕНИЕ
  network_id     = yandex_vpc_network.network-diplom.id
  # Без route_table_id
}

resource "yandex_vpc_gateway" "gateway-route-table" {
  name = "gateway-route-table"
  shared_egress_gateway {}
}

resource "yandex_vpc_route_table" "a-b-subnet-route-table" {
  name       = "a-b-subnet-route-table"
  network_id = yandex_vpc_network.network-diplom.id

  static_route {
    destination_prefix = "0.0.0.0/0"
    gateway_id         = yandex_vpc_gateway.gateway-route-table.id
  }
}

## Security_groups
resource "yandex_vpc_security_group" "bastion-security-local" {
  name        = "bastion-security-local"
  description = "Bastion security for local ip"
  network_id  = yandex_vpc_network.network-diplom.id

  ingress {
    protocol       = "TCP"
    description    = "IN to 22 port from local ip"
    v4_cidr_blocks = ["192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24"]
    port           = 22
  }

  egress {
    protocol       = "TCP"
    description    = "OUT from 22 port to local ip"
    v4_cidr_blocks = ["192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24"]
    port           = 22
  }

  egress {
    protocol       = "ANY"
    description    = "OUT from any ip"
    v4_cidr_blocks = ["0.0.0.0/0"]
    from_port      = 0
    to_port        = 65535
  }
}

resource "yandex_vpc_security_group" "bastion-security" {
  name        = "bastion-security"
  description = "Bastion security to connect to bastion"
  network_id  = yandex_vpc_network.network-diplom.id

  ingress {
    protocol          = "TCP"
    description       = "IN to 22 port from any ip"
    v4_cidr_blocks    = ["0.0.0.0/0"]
    port              = 22
  }

  egress {
    protocol          = "ANY"
    description       = "OUT from any ip"
    v4_cidr_blocks    = ["0.0.0.0/0"]
    from_port         = 0
    to_port           = 65535
  }

  ingress {
    protocol          = "TCP"
    description       = "IN to 22 port from local ip"
    security_group_id = yandex_vpc_security_group.bastion-security-local.id
    port              = 22
  }

  egress {
    protocol          = "TCP"
    description       = "OUT from 22 port to local ip"
    security_group_id = yandex_vpc_security_group.bastion-security-local.id
    port              = 22
  }
}

resource "yandex_vpc_security_group" "nginx-web-security" {
  name        = "nginx-web-security"
  description = "Nginx-web security"
  network_id  = yandex_vpc_network.network-diplom.id

  ingress {
    protocol       = "ANY"
    description    = "IN to 80 port from any ip"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 80
  }

  egress {
    protocol       = "ANY"
    description    = "OUT from 80 port to any ip"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 80
  }

  ingress {
    protocol       = "ANY"
    description    = "IN to 10050 port from any ip"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 10050
  }

  egress {
    protocol       = "ANY"
    description    = "OUT from 10050 port to any ip"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 10050
  }
}

resource "yandex_vpc_security_group" "zabbix-security" {
  name        = "zabbix-security"
  description = "Zabbix security"
  network_id  = yandex_vpc_network.network-diplom.id

  ingress {
    protocol       = "TCP"
    description    = "IN to 80 port from any ip"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 80
  }

  egress {
    protocol       = "TCP"
    description    = "OUT from 80 port to any ip"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 80
  }

  ingress {
    protocol       = "TCP"
    description    = "IN to 10051 from local ip"
    v4_cidr_blocks = ["192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24"]
    port           = 10051
  }

  egress {
    protocol       = "TCP"
    description    = "OUT from 10051 port to local ip"
    v4_cidr_blocks = ["192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24"]
    port           = 10051
  }
}

resource "yandex_vpc_security_group" "elasticsearch-security" {
  name        = "elasticsearch-security"
  description = "Elasticsearch security"
  network_id  = yandex_vpc_network.network-diplom.id

  ingress {
    protocol       = "TCP"
    description    = "IN to 9200 port from local ip"
    v4_cidr_blocks = ["192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24"]
    port           = 9200
  }

  egress {
    protocol       = "TCP"
    description    = "OUT from 9200 port to local ip"
    v4_cidr_blocks = ["192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24"]
    port           = 9200
  }

  ingress {
    protocol       = "ANY"
    description    = "IN to 10050 port from any ip"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 10050
  }

  egress {
    protocol       = "ANY"
    description    = "OUT from 10050 port to any ip"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 10050
  }
}

resource "yandex_vpc_security_group" "kibana-security" {
  name        = "kibana-security"
  description = "Kibana security"
  network_id  = yandex_vpc_network.network-diplom.id

  ingress {
    protocol       = "ANY"
    description    = "IN to 10050 port from any ip"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 10050
  }

  egress {
    protocol       = "ANY"
    description    = "OUT from 10050 to any ip"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 10050
  }

  ingress {
    protocol       = "TCP"
    description    = "IN to 5601 port from any ip"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 5601
  }

  egress {
    protocol       = "TCP"
    description    = "OUT from 5601 to any ip"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 5601
  }
}

resource "yandex_vpc_security_group" "filebeat-security" {
  name        = "filebeat-security"
  description = "Filebeat security"
  network_id  = yandex_vpc_network.network-diplom.id

  ingress {
    protocol       = "TCP"
    description    = "IN to 5044 port from local ip"
    v4_cidr_blocks = ["192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24"]
    port           = 5044
  }

  egress {
    protocol       = "TCP"
    description    = "OUT from 5044 to local ip"
    v4_cidr_blocks = ["192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24"]
    port           = 5044
  }
}

## Источник образа Ubuntu 22.04
data "yandex_compute_image" "ubuntu" {
  family = "ubuntu-2204-lts"
}

## Bastion
resource "yandex_compute_instance" "bastion" {
  name        = "bastion"
  hostname    = "bastion"
  zone        = "ru-central1-d"  # ПРОСТОЕ ЗНАЧЕНИЕ
  platform_id = "standard-v3"
  
  resources {
    cores         = 2
    core_fraction = 20
    memory        = 2
  }

  boot_disk {
    initialize_params {
      image_id = data.yandex_compute_image.ubuntu.id
      size     = 10
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.d-subnet-diplom.id
    nat       = true
    ipv4      = true
    ip_address = "192.168.30.3"
    security_group_ids = [yandex_vpc_security_group.bastion-security.id]
  }

  metadata = {
    ssh-keys = "ubuntu:${file("/home/alex/.ssh/id_ed25519.pub")}"
  }
}
```
##### Резервное копирование.
- Создать snapshot дисков всех ВМ. 
- Ограничить время жизни snaphot в неделю. 
- Сами snaphot настроить на ежедневное копирование.
```terraform
## Snapshot_schedule
resource "yandex_compute_snapshot_schedule" "snapshot-diplom" {
  name = "snapshot-diplom"

  schedule_policy {
    expression = "30 22 * * *"
  }

  snapshot_count = 7

  snapshot_spec {
    description = "Snapshots. Every day at 01:30"
  }

  disk_ids = [
    yandex_compute_instance.bastion.boot_disk.0.disk_id,
    yandex_compute_instance.nginx-web-1.boot_disk.0.disk_id,
    yandex_compute_instance.nginx-web-2.boot_disk.0.disk_id,
    yandex_compute_instance.zabbix.boot_disk.0.disk_id,
    yandex_compute_instance.elasticsearch.boot_disk.0.disk_id,
    yandex_compute_instance.kibana.boot_disk.0.disk_id
  ]
}
```

---

### 2.2 Запуск terraform playbook.
```bash
terraform apply
```
![2.1](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.1.png)

---

### 2.3 Проверка развернутых ресурсов в Yandex Cloud.
![2.2](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.2.png)
![2.3](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.3.png)
![2.4](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.4.png)
![2.5](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.5.png)
![2.6](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.6.png)
![2.7](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.7.png)
![2.8](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.8.png)
![2.9](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.9.png)
![2.10](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.10.png)
![2.11](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.11.png)
![2.12](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.12.png)
![2.13](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.13.png)
![2.14](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.14.png)
![2.15](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.15.png)
![2.16](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.16.png)

#### Все ресурсы через terraform развернуты и работают. 

---

### 2.4 Заполнение конфигурационного файла ansible `ansible.cfg` и inventory `inventory.ini` для выполнения задач дипломной работы.

Ссылки на файлы ansible: 

[ansible.cfg](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20ansible/ansible.cfg)

[inventory.ini](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20ansible/inventory.ini)

##### `ansible.cfg`. Раскоментировал и заполнил следующие строки.
```ansible
inventory=~/inventory.ini
host_key_checking=False
remote_user=alex
private_key_file=/home/alex/.ssh/id_ed25519
become=True
```
##### `inventory.ini`. Настроил подключение к ресурсам через ProxyCommand.
```ansible
[nginx-web]
nginx1 ansible_host=nginx-web-1.ru-central1.internal
nginx2 ansible_host=nginx-web-2.ru-central1.internal

[zabbix_servers]
zabbix-host ansible_host=zabbix.ru-central1.internal

[elasticsearch_cluster]
es-node ansible_host=elasticsearch.ru-central1.internal

[kibana_servers]
kibana-instance ansible_host=kibana.ru-central1.internal

[all:vars]
#ansible_ssh_common_args=-o ProxyCommand="ssh -W %h:%p -q ubuntu@158.160.186.92"
ansible_ssh_common_args=-o ProxyCommand="ssh -W %h:%p -q ubuntu@158.160.186.92" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
ansible_user=ubuntu
ansible_ssh_private_key_file=~/.ssh/id_ed25519
```

---

### 2.5 Файл с сайтом и ansible-playbooks для установки и конфигурирования необходимых сервисов.
Ссылка на файл с сайтом:

[index.nginx-ubuntu.html](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20ansible/index.nginx-ubuntu.html)

[playbook-nginx-web.yaml](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20ansible/playbook-nginx-web.yaml)

[playbook-zabbix.yaml](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20ansible/playbook-zabbix.yaml)

[playbook-zabbix-agent.yaml](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20ansible/playbook-zabbix-agent.yaml)

[playbook-elasticsearch.yaml](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20ansible/playbook-elasticsearch.yaml)

[playbook-kibana.yaml](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20ansible/playbook-kibana.yaml)

[playbook-filebeat.yaml](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20ansible/playbook-filebeat.yaml)

[playbook-filebeat2.yaml](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20ansible/playbook-filebeat2.yaml)

Ссылки на конфигурационные файлы:

[elasticsearch.yml](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20ansible/elasticsearch.yml)

[kibana.yml](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20ansible/kibana.yml)

[filebeat.yml](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20ansible/filebeat.yml)

[filebeat2.yml](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/files%20ansible/filebeat2.yml)

##### Сайт. Веб-сервера. Nginx.

Устанавливаю сервер nginx на 2 ВМ. Заменяю стандартный файл `index.nginx-debian.html`
```ansible
---
- name: "install nginx --> replacing a file index.nginx-ubuntu.html --> restart nginx"
  hosts: nginx-web
  become: true

  tasks:
  - name: "1/5 apt update"
    apt:
      update_cache: yes

  - name: "2/5 install nginx"
    apt:
      name: nginx
      state: latest

  - name: "3/5 replacing a file 'index.nginx-ubuntu.html' for nginx-web"
    copy:
        src: /home/alex/index.nginx-ubuntu.html
        dest: /var/www/html/index.nginx-ubuntu.html
        owner: www-data
        group: www-data

  - name: "4/5Update nginx config"
    replace:
        path: /etc/nginx/sites-available/default
        regexp: 'index .*;'
        replace: 'index index.nginx-ubuntu.html index.html index.htm;'

  - name: "5/5 restart Nginx"
    systemd:
      name: nginx
      state: restarted
```
![2.17](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.17.png)

##### Мониторинг. Zabbix. Zabbix-agent.

Разворачиваю Zabbix.
```ansible
---
- name: "download and install zabbix"
  hosts: zabbix_servers
  become: true

  tasks:
  - name: "1/8 apt update"
    apt:
      update_cache: yes

  - name: "2/8 install  postgresql"
    apt:
      name: postgresql
      state: latest

  - name: "3/8 download zabbix"
    get_url:
      url: https://repo.zabbix.com/zabbix/6.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.0-4+ubuntu22.04_all.deb
      dest: "/home/ubuntu"

  - name: "4/8 dpkg -i zabbix"
    apt:
      deb: /home/ubuntu/zabbix-release_6.0-4+ubuntu22.04_all.deb

  - name: "5/8 apt update"
    apt:
      update_cache: yes

  - name: "6/8 install zabbix-server-pgsql, zabbix-frontend-php, php8.2-pgsql, zabbix-apache-conf, zabbix-sql-scripts, zabbix-agent"
    apt:
      name:
      - zabbix-server-pgsql
      - zabbix-frontend-php
      - zabbix-apache-conf
      - zabbix-sql-scripts
      - zabbix-agent
      state: latest

  - name: "7/8 create user and database zabbix, import initial schema and data, configure DBPassword"
    shell: |
      su - postgres -c 'psql --command "CREATE USER zabbix WITH PASSWORD '\'123456789\'';"'
      su - postgres -c 'psql --command "CREATE DATABASE zabbix OWNER zabbix;"'
      zcat /usr/share/zabbix-sql-scripts/postgresql/server.sql.gz | sudo -u zabbix psql zabbix
      sed -i 's/# DBPassword=/DBPassword=123456789/g' /etc/zabbix/zabbix_server.conf

  - name: "8/8 restart and enable zabbix-server and apache"
    shell: |
      systemctl restart zabbix-server apache2
      systemctl enable zabbix-server apache2
```
![2.18](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.18.png)

На каждую ВМ устанавливаю Zabbix Agent, настраиваю агенты на отправление метрик в Zabbix.

```ansible
---
- name: "download and install zabbix-agent"
  hosts: nginx-web,elasticsearch_cluster,kibana_servers
  become: true

  tasks:
  - name: "1/7 apt update"
    apt:
      upgrade: yes
      update_cache: yes

  - name: "2/7 download zabbix-agent"
    get_url:
      url: https://repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_latest_7.0+ubuntu22.04_all.deb
      dest: "/home/ubuntu"

  - name: "3/7 dpkg -i zabbix-agent"
    apt:
      deb: /home/ubuntu/zabbix-release_latest_7.0+ubuntu22.04_all.deb

  - name: "4/7 apt update"
    apt:
      update_cache: yes

  - name: "5/7 apt install zabbix-agent"
    apt:
      name: zabbix-agent

  - name: "6/7 ip replacement in zabbix_agentd.conf"
    shell: |
      sed -i 's/Server=127.0.0.1/Server=192.168.30.4/g' /etc/zabbix/zabbix_agentd.conf

  - name: "7/7 restart and enable zabbix-agent"
    shell: |
      systemctl restart zabbix-agent
      systemctl enable zabbix-agent
```
![2.19](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.19.png)

##### Логи. Elasticsearch. Kibana. Filebeat.

Разворачиваю на ВМ Elasticsearch.
```ansible
---
- name: "download and install elasticsearch"
  hosts: elasticsearch_cluster
  become: true

  tasks:
  - name: "1/5 install gnupg and apt-transport-https"
    apt:
      name:
      - gnupg
      - apt-transport-https
      state: present

  - name: "2/5 download elasticsearch"
    get_url:
      url: https://mirror.yandex.ru/mirrors/elastic/7/pool/main/e/elasticsearch/elasticsearch-7.17.9-amd64.deb
      dest: "/home/ubuntu"

  - name: "3/5 dpkg -i elasticsearch"
    apt:
      deb: /home/ubuntu/elasticsearch-7.17.9-amd64.deb

  - name: "4/5 elasticsearch configuration 'elasticsearch.yml'"
    copy:
      src: /home/alex/elasticsearch.yml
      dest: /etc/elasticsearch/elasticsearch.yml

  - name: "5/5 enable and start elasticsearch"
    shell: |
      systemctl daemon-reload
      systemctl enable elasticsearch.service
      systemctl start elasticsearch.service
```
![2.20](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.20.png)
Разворачиваю на другой ВМ Kibana, конфигурирую соединение с Elasticsearch и добавляю параметр `server.publicBaseUrl: "http://51.250.37.133:5601"` в конфигурационный файл `kibana.yml`
![2.21](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.21.1.png)

```ansible
---
- name: "download and install kibana"
  hosts: kibana_servers
  become: true

  tasks:
  - name: "1/5 install gnupg and apt-transport-https"
    apt:
      name:
      - gnupg
      - apt-transport-https
      state: present

  - name: "2/5 download kibana"
    get_url:
      url: https://mirror.yandex.ru/mirrors/elastic/7/pool/main/k/kibana/kibana-7.17.9-amd64.deb
      dest: "/home/ubuntu"

  - name: "3/5 dpkg -i kibana"
    apt:
      deb: /home/ubuntu/kibana-7.17.9-amd64.deb

  - name: "4/5 kibana configuration 'kibana.yml'"
    copy:
      src: /home/alex/kibana.yml
      dest: /etc/kibana/kibana.yml

  - name: "5/5 enable and start kibana"
    shell: |
      systemctl daemon-reload
      systemctl enable kibana.service
      systemctl start kibana.service
```
![2.21](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.21.png)

Устанавливаю Filebeat в ВМ к веб-серверам, настраиваю на отправку access.log, error.log nginx в Elasticsearch.

```ansible
---
- name: "download and install filebeat for nginx-web-1"
  hosts: nginx1
  become: true

  tasks:
  - name: "1/5 install gnupg and apt-transport-https"
    apt:
      name:
      - gnupg
      - apt-transport-https
      state: present

  - name: "2/5 download filebeat"
    get_url:
      url: https://mirror.yandex.ru/mirrors/elastic/7/pool/main/f/filebeat/filebeat-7.17.9-amd64.deb
      dest: "/home/ubuntu"

  - name: "3/5 dpkg -i filebeat"
    apt:
      deb: /home/ubuntu/filebeat-7.17.9-amd64.deb

  - name: "4/5 copy config file for filebeat"
    copy:
      src: /home/alex/filebeat.yml
      dest: /etc/filebeat/

  - name: "5/5 enable and start filebeat"
    shell: |
      systemctl deamon-reload
      systemctl enable filebeat.service
      systemctl start filebeat.service
```
![2.22](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.22.png)
```ansible
---
- name: "download and install filebeat for nginx-web-2"
  hosts: nginx2
  become: true

  tasks:
  - name: "1/5 install gnupg and apt-transport-https"
    apt:
      name:
      - gnupg
      - apt-transport-https
      state: present

  - name: "2/5 download filebeat"
    get_url:
      url: https://mirror.yandex.ru/mirrors/elastic/7/pool/main/f/filebeat/filebeat-7.17.9-amd64.deb
      dest: "/home/ubuntu"

  - name: "3/5 dpkg -i filebeat"
    apt:
      deb: /home/ubuntu/filebeat-7.17.9-amd64.deb

  - name: "4/5 copy config file for filebeat"
    copy:
      src: /home/alex/filebeat2.yml
      dest: /etc/filebeat/filebeat.yml

  - name: "5/5 enable and start filebeat"
    shell: |
      systemctl deamon-reload
      systemctl enable filebeat.service
      systemctl start filebeat.service
```
![2.23](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.23.png)

#### Все сервисы через ansible развернуты.

---

### 2.6 Проверка и настройка ресурсов для выполнения задач дипломной работы.

##### Сайт.
Протестирую работу сайта с ip балансировщика.
```bash
curl -v 158.160.177.66:80
```
![2.24](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.24.png)

Просмотр сайта с браузера:

![2.25](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.25.png)

##### Мониторинг.
Проверка работы Zabbix. Перехожу на страницу с Zabbix `http://158.160.202.216/zabbix`.

![2.26](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.26.png)
![2.27](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.27.png)
![2.28](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.28.png)
![2.29](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.29.png)
![2.30](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.30.png)
![2.31](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.31.png)

Вхожу, используя логин - Admin, пароль - zabbix.

![2.32](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.32.png)

Создаю Template.

![2.33](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.33.png)

Добавляю хосты.

![2.34](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.34.png)

Настраиваю дешборды с отображением метрик, минимальный набор — по принципу USE (Utilization, Saturation, Errors) для CPU, RAM, диски, сеть, http запросов к веб-серверам.

![2.35](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.35.png)

##### Логи.
Захожу в kibana `http://158.160.185.105:5601/`

![2.36](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.36.png)

Создаю Index patterns.

![2.37](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.37.png)
![2.38](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.38.png)
![2.39](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.39.png)
![2.40](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.40.png)

Смотрю отправляются ли логи.

![2.41](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.41.png)
![2.42](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.42.png)

##### Резервное копирование.
Резервное копирование настроено на 1:30, но оно настроено с учетом разницы во времени с Yandex Cloud, время по MSK 22:30.

![2.43](https://github.com/IMiroxxI/Diplom_Netology/blob/main/02_Выполнение%20дипломонй%20работы/img/2.43.png)

Заключительная часть в 03_Заключение.
