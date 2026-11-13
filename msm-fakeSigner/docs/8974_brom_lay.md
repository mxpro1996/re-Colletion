## MSM8974/8612 Bootrom laystack
```c
// Refer from https://nlitsme.github.io/2019/11/msm-8974-bootrom/
f8002000 - app bootrom struct

fc000000-fc002c28 - RPM bootrom
fc004000-fc010000 - Modem bootrom
fc010000-fc02f800 - APP bootrom
fc02f800-fc02fa08 - RPM bootrom part2

fc100080 - bootrom error stack
There is a event log buffer at 0xFC102144, and a fatal error buffer at 0xFC102084 which can be interrogated using the sahara protocol.

```
