#!/bin/sh -ex

tc qdisc add root dev dtls0 cake bandwidth 2500Kbit
