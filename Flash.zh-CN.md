# 创建nvs-creds.bin

创建`nvs-creds.bin`文件，用于存储设备专属的私钥和设备GUID。这些信息与具体设备绑定，在OTA升级过程中必须保持不变。

## 默认MQTT Broker

```bash
python D:/Espressif/frameworks/esp-idf-v5.5.5/components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py generate nvs-creds-default.csv nvs-creds.bin 0x1000
```

**提示：** 请将`D:/Espressif/frameworks/esp-idf-v5.5.5`替换为您本机实际的ESP-IDF安装路径。

## AWS MQTT Broker

```bash
python D:/Espressif/frameworks/esp-idf-v5.5.5/components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py generate nvs-creds-aws.csv nvs-creds.bin 0x1000
```

## 擦除Flash

```bash
esptool.py --port COM4 erase_flash
```

## 将凭证文件烧录至Flash

**注意：** `0xA000`必须与分区表中NVS分区的起始地址一致。

```bash
esptool.py --port COM4 write_flash 0xA000 nvs-creds.bin
```