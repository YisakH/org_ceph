#!/bin/bash

ssh -N -R 10113:localhost:22 yshong@drm05003.iptime.org -p 10022 -o ServerAliveInterval=60 -o ServerAliveCountMax=3
