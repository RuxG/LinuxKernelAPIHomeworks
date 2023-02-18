# linux-homework

This repo contains two homeworks as part of the Operating Systems university course.

The first assignment, **assignment0**, implements a simple kernel module that holds an internal list. A user can store, remove and list string elements from the list. The purpose of the homework was to familiarize with the linux kernel modules API.

The second assignment, **assignment1**, implements a kernel module capable of tracing kernel operations, based on the **Kernel Probes** mechanism. The user can track calls to operations such as __kmalloc & kfree__, **schedule**, **mutex_lock & mutex_unlock**, **up_interruptible & down_interruptible**.
