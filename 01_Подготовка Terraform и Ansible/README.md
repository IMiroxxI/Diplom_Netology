## 1.0 Установка и подготовка Terraform и Ansible.
### 1.1 Подготовка Terraform.
Распаковываю скачанный архив с https://hashicorp-releases.yandexcloud.net/terraform/
```bash
zcat terraform_1.7.0_linux_amd64.zip > terraform-diplom
chmod 744 terraform-diplom
sudo mv terraform-diplom /usr/local/bin/
terraform-diplom -version
```
![1.1](https://github.com/IMiroxxI/Diplom_Netology/blob/main/01_Подготовка%20Terraform%20и%20Ansible/img/1.1.png)

Создаю файл `.terraformrc` и добавляю блок с источником, из которого будет устанавливаться провайдер.
```bash
nano ~/.terraformrc
```
```terraform
provider_installation {
  network_mirror {
    url = "https://terraform-mirror.yandexcloud.net/"
    include = ["registry.terraform.io/*/*"]
  }
  direct {
    exclude = ["registry.terraform.io/*/*"]
  }
}
```
![1.2](https://github.com/IMiroxxI/Diplom_Netology/blob/main/01_Подготовка%20Terraform%20и%20Ansible/img/1.2.png)

Для файла с метаданными, `meta.yaml`, использую ранее создаваемый ssh ключ для доступа к Yandex Cloud.

Создаю файл `meta.yaml` с данными пользователя на создаваемые ВМ.
```bash
nano ~/meta.yaml
```
```terraform
#cloud-config
 users:
  - name: alexandr
    groups: sudo
    shell: /bin/bash
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    ssh-authorized-keys:
      - ssh-ed25519
```
![1.3](https://github.com/IMiroxxI/Diplom_Netology/blob/main/01_Подготовка%20Terraform%20и%20Ansible/img/1.3.png)
```
```terraform
terraform {
  required_providers {
    yandex = {
      source = "yandex-cloud/yandex"
    }
  }
}
```
![1.4](https://github.com/IMiroxxI/Diplom_Netology/blob/main/01_Подготовка%20Terraform%20и%20Ansible/img/1.4.png)
Инициализирую провайдера.
```bash
Diplom init
```
![1.5](https://github.com/IMiroxxI/Diplom_Netology/blob/main/01_Подготовка%20Terraform%20и%20Ansible/img/1.5.png)
#### Terraform готов к использованию.

### 1.2 Подготовка Ansible.
Ansible у меня уже установлен, поэтому проверяю.
```bash
ansible --version
```
![1.6](https://github.com/IMiroxxI/Diplom_Netology/blob/main/01_Подготовка%20Terraform%20и%20Ansible/img/1.6.png)
Далее делаю подготовку файла `ansible.cfg`.
Создаю файл `inventory.ini` и добавляю в него начальные данные.
```bash
nano ~/inventory.ini
```
Файлы прикрепил в 02_Выполнение дипломной работы.
