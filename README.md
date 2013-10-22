wildstring
==========
Это модуль ядра Linux, сделанный на основе xt_string и позволяющий искать одновременно до трёх последовательностей символов в пакете.

Последовательности разделяются символом "*" и ищутся в пакете по очереди.

## Как использовать для HTTP

Стоит учитывать то, что в HTTP пакете GET идёт перед HOST, так что чтобы блокировать текстовые файлы связанные с Carbon Reductor на сайте carbonsoft.ru нужно применить следующий шаблон:
```
iptables -I FORWARD -p tcp --dport 80 --tcp-flags PSH,ACK PSH,ACK -m wildstring --wildstring "reductor*txt*carbonsoft.ru" -j DROP
```
