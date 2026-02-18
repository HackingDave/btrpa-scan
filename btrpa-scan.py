#!/usr/bin/env python3
#
# btrpa-scan - Bluetooth Low Energy (BLE) Scanner with RPA Resolution
#
# Written by: David Kennedy (@HackingDave)
# Company:    TrustedSec
# Website:    https://www.trustedsec.com
#
# A BLE scanner that discovers broadcasting devices, searches for specific
# targets by MAC address, and resolves Resolvable Private Addresses (RPAs)
# using Identity Resolving Keys (IRKs) per the Bluetooth Core Specification.
#

"""Bluetooth LE scanner - scan all devices or search for a specific one."""

import argparse
import asyncio
import csv
import json
import os
import platform
import re
import signal
import socket
import webbrowser
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
except ImportError:
    print("Error: 'bleak' is not installed.")
    print("Install dependencies with:  pip install -r requirements.txt")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("Error: 'cryptography' is not installed.")
    print("Install dependencies with:  pip install -r requirements.txt")
    sys.exit(1)

_HAS_CURSES = False
try:
    import curses
    _HAS_CURSES = True
except ImportError:
    pass

_HAS_FLASK = False
try:
    from flask import Flask, render_template_string, jsonify
    from flask_socketio import SocketIO
    _HAS_FLASK = True
except ImportError:
    pass

# Environment path loss exponents for distance estimation
_ENV_PATH_LOSS = {
    "free_space": 2.0,
    "outdoor": 2.2,
    "indoor": 3.0,
}

# Default reference-RSSI offset (dB) subtracted from TX Power to estimate
# the expected RSSI at the 1-metre reference distance.  The theoretical
# free-space path loss at 1 m for 2.4 GHz is ~41 dB, but real BLE devices
# add ~18 dB of antenna inefficiency, enclosure loss, and polarisation
# mismatch.  The iBeacon standard uses -59 dBm at 1 m for 0 dBm TX,
# which corresponds to an offset of 59.
_DEFAULT_REF_OFFSET = 59

# Polling / timing constants
_TUI_REFRESH_INTERVAL = 0.3       # seconds between TUI redraws
_SCAN_POLL_INTERVAL = 0.5         # seconds between poll cycles (continuous)
_TIMED_SCAN_POLL_INTERVAL = 0.1   # seconds between poll cycles (timed)
_GPS_RECONNECT_DELAY = 5          # seconds before GPS reconnect attempt
_GPS_SOCKET_TIMEOUT = 5           # seconds for GPS socket operations
_GPS_STARTUP_DELAY = 0.5          # seconds to wait for initial GPS connection

_FIELDNAMES = [
    "timestamp", "address", "name", "rssi", "avg_rssi", "tx_power",
    "est_distance", "latitude", "longitude", "gps_altitude",
    "manufacturer_data", "service_uuids", "resolved",
]

_BANNER = r"""
  _     _
 | |__ | |_ _ __ _ __   __ _       ___  ___ __ _ _ __
 | '_ \| __| '__| '_ \ / _` |_____/ __|/ __/ _` | '_ \
 | |_) | |_| |  | |_) | (_| |_____\__ \ (_| (_| | | | |
 |_.__/ \__|_|  | .__/ \__,_|     |___/\___\__,_|_| |_|
                |_|
   BLE Scanner with RPA Resolution
   by @HackingDave | TrustedSec
"""

_GUI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BTRPA-SCAN</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0a0a;--card:#1a1a1a;--border:#333;--text:#e0e0e0;
  --green:#00ff41;--cyan:#00e5ff;--yellow:#ffff00;--red:#ff4444;--dim:#666;
}
html,body{height:100%;background:var(--bg);color:var(--text);
  font-family:'Fira Code',Consolas,'Courier New',monospace;font-size:13px;
  overflow:hidden;position:relative;display:flex;flex-direction:column}

/* ── matrix data rain background ─────────────────────────── */
#matrix-bg{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
#matrix-bg canvas{width:100%;height:100%}
/* everything else above the rain */
#header,#panels,#tooltip,#overlay{position:relative;z-index:1}
a{color:var(--cyan)}

/* ── header bar ────────────────────────────────────────────── */
#header{display:flex;align-items:center;gap:18px;padding:8px 16px;
  background:#111;border-bottom:1px solid var(--border);flex-wrap:wrap}
#header .title{color:var(--green);font-weight:700;font-size:16px;letter-spacing:1px}
#header .stat{color:var(--text);font-size:12px}
#header .stat b{color:var(--green)}
#header .meta{font-size:11px;color:var(--dim);width:100%}

/* ── main panels ───────────────────────────────────────────── */
#panels{display:flex;flex:1;min-height:0}
#radar-wrap{flex:3;position:relative;background:var(--card);
  border-right:1px solid var(--border);min-width:0}
#radar-canvas{width:100%;height:100%;display:block}
#map-wrap{flex:2;position:relative;min-width:0}
#map-wrap.hidden{display:none}
#radar-wrap.full{flex:1}
#map{width:100%;height:100%}

/* ── right-side device list ─────────────────────────────────── */
#device-list{width:260px;min-width:200px;background:#111;
  border-left:1px solid var(--border);overflow-y:auto;overflow-x:hidden;
  display:flex;flex-direction:column}
#device-list .dl-header{padding:8px 10px;color:var(--green);font-size:11px;
  font-weight:700;letter-spacing:1px;border-bottom:1px solid var(--border);
  text-transform:uppercase;flex-shrink:0}
#device-list .dl-scroll{flex:1;overflow-y:auto;padding:4px 0}
.dev-entry{padding:6px 10px;border-left:3px solid var(--dim);cursor:pointer;
  transition:background .15s;font-size:11px;line-height:1.5;
  border-bottom:1px solid #1a1a1a}
.dev-entry:hover{background:#1a2a1a}
.dev-entry.pinned{background:#1a1a2a}
.dev-entry .de-addr{color:var(--text);font-weight:600;font-size:12px}
.dev-entry .de-name{color:var(--dim);font-size:10px;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.dev-entry .de-meta{display:flex;justify-content:space-between;
  font-size:10px;color:var(--dim);margin-top:2px}
.dev-entry .de-rssi{font-weight:600}
.dev-entry .de-pin{float:right;color:var(--dim);font-size:10px;opacity:0;
  transition:opacity .15s}
.dev-entry:hover .de-pin{opacity:1}
.dev-entry.pinned .de-pin{opacity:1;color:var(--cyan)}
/* signal strength border colors */
.dev-entry.sig-close{border-left-color:var(--green)}
.dev-entry.sig-medium{border-left-color:var(--yellow)}
.dev-entry.sig-far{border-left-color:var(--red)}
.dev-entry.sig-unknown{border-left-color:var(--dim)}

/* ── left-side pinned panel ────────────────────────────────── */
#pinned-panel{width:240px;min-width:180px;background:#111;
  border-right:1px solid var(--border);overflow-y:auto;overflow-x:hidden;
  display:none;flex-direction:column}
#pinned-panel.visible{display:flex}
#pinned-panel .pp-header{padding:8px 10px;color:var(--cyan);font-size:11px;
  font-weight:700;letter-spacing:1px;border-bottom:1px solid var(--border);
  text-transform:uppercase;flex-shrink:0}
#pinned-panel .pp-scroll{flex:1;overflow-y:auto;padding:4px 0}
.pin-entry{padding:6px 10px;font-size:11px;line-height:1.5;
  border-bottom:1px solid #1a1a1a;display:flex;align-items:center;
  justify-content:space-between;border-left:3px solid var(--cyan)}
.pin-entry .pe-addr{color:var(--text);font-weight:600;font-size:12px}
.pin-entry .pe-name{color:var(--dim);font-size:10px}
.pin-entry .pe-meta{font-size:10px;color:var(--dim)}
.pin-entry .pe-close{cursor:pointer;color:var(--red);font-size:14px;
  font-weight:700;padding:0 4px;opacity:0.6;transition:opacity .15s}
.pin-entry .pe-close:hover{opacity:1}

/* ── signal strength bars ─────────────────────────────────── */
.signal-bar-wrap{height:4px;background:#222;border-radius:2px;margin-top:4px;
  overflow:hidden;position:relative}
.signal-bar{height:100%;border-radius:2px;transition:width .4s ease,background .4s ease;
  min-width:2px}
.signal-bar.sig-green{background:linear-gradient(90deg,#00cc33,#00ff41)}
.signal-bar.sig-yellow{background:linear-gradient(90deg,#cc9900,#ffff00)}
.signal-bar.sig-red{background:linear-gradient(90deg,#aa2222,#ff4444)}
.signal-bar.sig-none{background:#444}
/* larger bar for pinned panel */
.pin-entry .signal-bar-wrap{height:6px;margin-top:5px}
.pin-entry .pe-trend{font-size:10px;font-weight:700;margin-left:6px}
.pin-entry .pe-trend.closer{color:var(--green)}
.pin-entry .pe-trend.farther{color:var(--red)}
.pin-entry .pe-trend.steady{color:var(--yellow)}
.pin-entry .pe-rssi-big{font-size:16px;font-weight:700;font-family:monospace;
  line-height:1.2;margin-top:2px}
.pin-entry .pe-dist-big{font-size:11px;color:var(--dim);margin-top:1px}
.pin-entry .pe-sparkline{margin-top:4px;display:block;width:100%;height:28px}

/* ── tooltip ───────────────────────────────────────────────── */
#tooltip{position:fixed;pointer-events:none;background:rgba(10,10,10,.94);
  border:1px solid var(--green);border-radius:4px;padding:10px 14px;
  font-size:11px;line-height:1.6;max-width:380px;z-index:9999;display:none;
  box-shadow:0 4px 20px rgba(0,255,65,.12)}
#tooltip .lbl{color:var(--dim)}
#tooltip .val{color:var(--text)}

/* ── scan-complete overlay ─────────────────────────────────── */
#overlay{position:fixed;inset:0;background:rgba(0,0,0,.82);display:none;
  justify-content:center;align-items:center;z-index:10000;
  animation:fadeIn .6s ease}
#overlay .card{background:var(--card);border:1px solid var(--green);
  border-radius:8px;padding:36px 48px;text-align:center;
  box-shadow:0 0 40px rgba(0,255,65,.15)}
#overlay h2{color:var(--green);font-size:22px;margin-bottom:12px}
#overlay p{font-size:14px;margin:4px 0;color:var(--text)}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}

/* ── activity log ticker ──────────────────────────────────── */
#activity-log{height:28px;background:#080808;border-top:1px solid var(--border);
  display:flex;align-items:center;padding:0 12px;overflow:hidden;
  flex-shrink:0;position:relative;z-index:1}
#activity-log .log-entries{display:flex;gap:24px;white-space:nowrap;
  font-size:10px;font-family:monospace;color:var(--green);opacity:0.7;
  overflow:hidden;flex:1}
#activity-log .log-entry{animation:log-slide-in .3s ease}
#activity-log .log-entry .log-ts{color:var(--dim)}
#activity-log .log-entry .log-type{font-weight:700}
#activity-log .log-entry .log-type.lt-new{color:var(--green)}
#activity-log .log-entry .log-type.lt-lost{color:var(--red)}
#activity-log .log-entry .log-type.lt-rssi{color:var(--yellow)}
#activity-log .log-entry .log-type.lt-irk{color:var(--cyan)}
#activity-log .log-entry .log-type.lt-pin{color:var(--cyan)}
@keyframes log-slide-in{from{opacity:0;transform:translateX(-20px)}to{opacity:1;transform:translateX(0)}}

/* ── boot sequence overlay ────────────────────────────────── */
#boot-overlay{position:fixed;inset:0;z-index:99999;background:#0a0a0a;
  display:flex;flex-direction:column;justify-content:center;align-items:center;
  cursor:pointer;transition:opacity .6s ease}
#boot-overlay.fade-out{opacity:0;pointer-events:none}
#boot-lines{font-family:'Fira Code',Consolas,monospace;font-size:13px;
  color:var(--green);max-width:600px;width:90%;line-height:2}
#boot-lines .boot-line{opacity:0;white-space:pre}
#boot-lines .boot-line.visible{opacity:1}
#boot-lines .boot-line .ok{color:#00ff41}
#boot-lines .boot-line .fail{color:#ff4444}
#boot-lines .boot-cursor{display:inline-block;width:8px;height:14px;
  background:var(--green);animation:blink-cursor .6s step-end infinite;
  vertical-align:middle;margin-left:2px}
@keyframes blink-cursor{50%{opacity:0}}

/* ── CRT scanline overlay + vignette ──────────────────────── */
body::after{content:"";position:fixed;inset:0;z-index:9998;pointer-events:none;
  background:
    repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 3px),
    radial-gradient(ellipse at center,transparent 60%,rgba(0,0,0,0.35) 100%);
  mix-blend-mode:multiply}

/* leaflet popup override */
.leaflet-popup-content-wrapper{background:var(--card)!important;
  color:var(--text)!important;border-radius:4px!important;font-size:12px}
.leaflet-popup-tip{background:var(--card)!important}
</style>
</head>
<body>

<!-- boot sequence overlay -->
<div id="boot-overlay">
  <div id="boot-lines"></div>
</div>

<!-- matrix data rain background -->
<div id="matrix-bg"><canvas id="matrix-canvas"></canvas></div>

<!-- header -->
<div id="header">
  <span class="title">BTRPA-SCAN</span>
  <span class="stat" id="s-dot" style="color:var(--green)">&bull;</span>
  <span class="stat"><b id="s-unique">0</b> devices</span>
  <span class="stat"><b id="s-total">0</b> detections</span>
  <span class="stat"><b id="s-elapsed">00:00</b> elapsed</span>
  <span class="stat" id="sound-toggle" style="cursor:pointer;color:var(--dim);user-select:none" title="Toggle audio pings">[SND:OFF]</span>
  <div class="meta" id="s-meta"></div>
</div>

<!-- pinned panel + radar + map + device list -->
<div id="panels">
  <div id="pinned-panel">
    <div class="pp-header">Pinned Devices</div>
    <div class="pp-scroll" id="pinned-scroll"></div>
  </div>
  <div id="radar-wrap" class="full">
    <canvas id="radar-canvas"></canvas>
  </div>
  <div id="map-wrap" class="hidden">
    <div id="map"></div>
  </div>
  <div id="device-list">
    <div class="dl-header">Detected Devices</div>
    <div class="dl-scroll" id="dl-scroll"></div>
  </div>
</div>

<!-- activity log ticker -->
<div id="activity-log">
  <div class="log-entries" id="log-entries"></div>
</div>

<!-- tooltip -->
<div id="tooltip"></div>

<!-- scan complete overlay -->
<div id="overlay">
  <div class="card">
    <h2>SCAN COMPLETE</h2>
    <p id="ov-elapsed"></p>
    <p id="ov-total"></p>
    <p id="ov-unique"></p>
  </div>
</div>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
<!-- inject Jinja2 port variable before raw block -->
<script>var WSPORT = {{ port }};</script>
""" + r"""{% raw %}""" + r"""
<script>
(function(){
"use strict";

/* ================================================================
   Boot Sequence
   ================================================================ */
var bootLines = [
  {text:"[INIT] btrpa-scan v1.0 \u2500\u2500 BLE Scanner with RPA Resolution", delay:0},
  {text:"[LOAD] Bluetooth LE adapter............. ", status:"OK", delay:80},
  {text:"[LOAD] RSSI calibration engine.......... ", status:"OK", delay:70},
  {text:"[LOAD] Radar display subsystem.......... ", status:"OK", delay:60},
  {text:"[LOAD] IRK resolution module............ ", status:"OK", delay:70},
  {text:"[LOAD] Distance estimation engine....... ", status:"OK", delay:60},
  {text:"[CONN] Scanner backend.................. ", status:"CONNECTED", delay:120},
  {text:"[BOOT] All systems nominal. Starting sweep...", delay:150},
];

(function runBoot(){
  var overlay = document.getElementById("boot-overlay");
  var container = document.getElementById("boot-lines");
  if(!overlay){ return; }
  var idx = 0;
  function showLine(){
    if(idx >= bootLines.length){
      // done — brief pause, then fade out
      setTimeout(function(){
        overlay.classList.add("fade-out");
        setTimeout(function(){ overlay.style.display="none"; }, 400);
      }, 250);
      return;
    }
    var bl = bootLines[idx];
    var div = document.createElement("div");
    div.className = "boot-line";
    var span = document.createElement("span");
    span.textContent = bl.text;
    div.appendChild(span);
    if(bl.status){
      var st = document.createElement("span");
      st.className = bl.status==="OK" || bl.status==="CONNECTED" ? "ok" : "fail";
      st.textContent = bl.status;
      div.appendChild(st);
    }
    // add blinking cursor to last line
    if(idx === bootLines.length - 1){
      var cur = document.createElement("span");
      cur.className = "boot-cursor";
      div.appendChild(cur);
    }
    container.appendChild(div);
    // trigger visibility
    requestAnimationFrame(function(){ div.classList.add("visible"); });
    idx++;
    setTimeout(showLine, bl.delay + 80);
  }
  showLine();
  // click anywhere to skip
  overlay.addEventListener("click", function(){
    overlay.classList.add("fade-out");
    setTimeout(function(){ overlay.style.display="none"; }, 300);
  });
})();

/* ================================================================
   State
   ================================================================ */
var devices = {};          // address -> device obj
var scannerGPS = null;     // {lat,lon,alt}
var hasGPS = false;
var hoveredAddr = null;
var pinnedAddrs = {};      // address -> true (pinned devices)

/* ================================================================
   Matrix Data Rain Background
   ================================================================ */
var mCanvas = document.getElementById("matrix-canvas");
var mCtx = mCanvas.getContext("2d");
var matrixCols = [];
var MATRIX_FONT_SIZE = 13;
var matrixW = 0;

function resizeMatrix(){
  mCanvas.width  = window.innerWidth;
  mCanvas.height = window.innerHeight;
  matrixW = Math.floor(mCanvas.width / MATRIX_FONT_SIZE);
  while(matrixCols.length < matrixW) matrixCols.push(Math.random()*mCanvas.height);
  matrixCols.length = matrixW;
  // clamp existing column Y-positions to new height
  for(var i=0;i<matrixW;i++){
    if(matrixCols[i]>mCanvas.height) matrixCols[i]=Math.random()*mCanvas.height;
  }
}
window.addEventListener("resize", resizeMatrix);
resizeMatrix();

// pool of data strings to rain — updated with real device data
var matrixPool = [
  "FF:E1:A0:3B:9C:22","0x004C","RSSI:-45","2.4GHz","BLE5.0","SCAN","RPA",
  "0xFEED","AES128","IRK","GATT","L2CAP","ADV_IND","CONNECT",
  "CH37","CH38","CH39","iBeacon","UUID","GAP","SMP",
];

function feedMatrixPool(){
  // rebuild pool from current devices (replaces stale entries)
  var seen = new Set(matrixPool.slice(0,21)); // keep base BLE terms
  var fresh = matrixPool.slice(0,21); // base pool
  var addrs = Object.keys(devices);
  for(var i=0;i<addrs.length&&fresh.length<200;i++){
    var d = devices[addrs[i]];
    if(!seen.has(d.address)){seen.add(d.address);fresh.push(d.address);}
    if(d.rssi!=null){var rStr="RSSI:"+d.rssi;if(!seen.has(rStr)){seen.add(rStr);fresh.push(rStr);}}
    if(d.name&&d.name!=="Unknown"&&!seen.has(d.name)){seen.add(d.name);fresh.push(d.name);}
    if(d.manufacturer_data){var mf=d.manufacturer_data.substring(0,16);if(!seen.has(mf)){seen.add(mf);fresh.push(mf);}}
  }
  matrixPool = fresh;
}

function getMatrixChar(col){
  // pick a character from the pool or random hex
  if(Math.random()<0.3){
    var s = matrixPool[Math.floor(Math.random()*matrixPool.length)];
    var ci = Math.floor(Math.random()*s.length);
    return s[ci];
  }
  return "0123456789ABCDEF"[Math.floor(Math.random()*16)];
}

var matrixFrameCount = 0;
function drawMatrix(){
  matrixFrameCount++;
  // full clear every ~30s (600 frames at 20fps) to prevent green haze buildup
  if(matrixFrameCount % 600 === 0){
    mCtx.fillStyle = "#0a0a0a";
    mCtx.fillRect(0,0,mCanvas.width,mCanvas.height);
  } else {
    mCtx.fillStyle = "rgba(10,10,10,0.08)";
    mCtx.fillRect(0,0,mCanvas.width,mCanvas.height);
  }
  mCtx.font = MATRIX_FONT_SIZE+"px monospace";
  for(var i=0;i<matrixW;i++){
    var x = i * MATRIX_FONT_SIZE;
    var y = matrixCols[i];
    var ch = getMatrixChar(i);
    // head character brighter
    mCtx.fillStyle = "rgba(0,255,65,0.25)";
    mCtx.fillText(ch, x, y);
    // trail character dimmer
    if(y > MATRIX_FONT_SIZE){
      mCtx.fillStyle = "rgba(0,255,65,0.06)";
      mCtx.fillText(ch, x, y - MATRIX_FONT_SIZE);
    }
    matrixCols[i] += MATRIX_FONT_SIZE;
    // reset column randomly or when off screen
    if(matrixCols[i] > mCanvas.height && Math.random()>0.975){
      matrixCols[i] = 0;
    }
  }
}
// update matrix pool every 5s with real device data
setInterval(feedMatrixPool, 5000);
// run matrix at ~20fps (independent of radar)
setInterval(drawMatrix, 50);

/* ================================================================
   Radar
   ================================================================ */
var rCanvas = document.getElementById("radar-canvas");
var rCtx    = rCanvas.getContext("2d");
var sweepAngle = 0;
var SWEEP_PERIOD = 4000; // ms per revolution
var RINGS = [1, 5, 10, 20]; // metres
var MAX_RING = 20;
var pingRipples = []; // {cx,cy,r,maxR,alpha,color,born}

// ── particle trail system ──
var particles = []; // {x,y,vx,vy,color,born,life,size}
var PARTICLE_MAX = 200;

function spawnParticles(x, y, color, count){
  for(var i=0;i<count&&particles.length<PARTICLE_MAX;i++){
    var angle = Math.random()*Math.PI*2;
    var speed = 0.3 + Math.random()*1.2;
    particles.push({
      x:x, y:y,
      vx:Math.cos(angle)*speed,
      vy:Math.sin(angle)*speed,
      color:color,
      born:Date.now(),
      life:500+Math.random()*500,
      size:1+Math.random()*2
    });
  }
}

function drawParticles(dpr){
  var now = Date.now();
  for(var i=particles.length-1;i>=0;i--){
    var p = particles[i];
    var age = now - p.born;
    if(age > p.life){ particles.splice(i,1); continue; }
    var progress = age / p.life;
    var alpha = (1-progress)*0.6;
    var sz = p.size * (1-progress*0.5) * dpr;
    p.x += p.vx;
    p.y += p.vy;
    p.vx *= 0.97;
    p.vy *= 0.97;
    rCtx.beginPath();
    rCtx.arc(p.x, p.y, sz, 0, Math.PI*2);
    rCtx.fillStyle = hexToRgba(p.color, alpha);
    rCtx.fill();
  }
}

function resizeCanvas(){
  var wrap = document.getElementById("radar-wrap");
  var dpr = window.devicePixelRatio||1;
  var newW = Math.floor(wrap.clientWidth * dpr);
  var newH = Math.floor(wrap.clientHeight * dpr);
  if(rCanvas.width === newW && rCanvas.height === newH) return;
  rCanvas.width  = newW;
  rCanvas.height = newH;
  rCanvas.style.width  = wrap.clientWidth  + "px";
  rCanvas.style.height = wrap.clientHeight + "px";
}
window.addEventListener("resize", resizeCanvas);
resizeCanvas();

function hashAddr(addr){
  var h=0;
  for(var i=0;i<addr.length;i++){h=((h<<5)-h)+addr.charCodeAt(i);h|=0;}
  return h<0?-h:h;
}
// secondary hash for radius jitter to separate dots at same angle
function hashAddr2(addr){
  var h=5381;
  for(var i=0;i<addr.length;i++){h=((h<<5)+h)^addr.charCodeAt(i);h|=0;}
  return h<0?-h:h;
}

function distToRadius(d, maxR){
  if(d==null||d===""||d<=0) return maxR*0.85;
  var clamped = Math.min(d, MAX_RING);
  return (Math.log(clamped+1)/Math.log(MAX_RING+1))*maxR;
}

function dotColor(d){
  if(d!=null&&d!==""&&d>0){
    if(d<5) return "#00ff41";
    if(d<=15) return "#ffff00";
    return "#ff4444";
  }
  return "#666666";
}

// RSSI-based color when distance is unavailable
// -60 and stronger = green (close), -60 to -80 = yellow (medium), below -80 = red (far)
function colorFromRssiOrDist(dev){
  var dist = dev.est_distance;
  if(dist!=null&&dist!==""&&dist>0) return dotColor(dist);
  var rssi = dev.rssi;
  if(rssi==null) return "#666666";
  if(rssi >= -60) return "#00ff41";
  if(rssi >= -80) return "#ffff00";
  return "#ff4444";
}

function hexToRgba(hex, a){
  var r=parseInt(hex.slice(1,3),16), g=parseInt(hex.slice(3,5),16), b=parseInt(hex.slice(5,7),16);
  return "rgba("+r+","+g+","+b+","+a+")";
}

/* ── ghost MAC flicker layer ────────────────────────────── */
// Ghosts: faint MAC addresses / data that materialize, flicker, and dissolve
// in the radar background. Each ghost has a lifecycle: fade in -> flicker -> fade out
var ghosts = []; // {text, x, y, born, lifespan, flickerRate, fontSize, angle}
var GHOST_MAX = 18;
var GHOST_SPAWN_INTERVAL = 400; // ms between spawns
var lastGhostSpawn = 0;

function spawnGhost(W, H, dpr){
  var addrs = Object.keys(devices);
  var text;
  if(addrs.length > 0 && Math.random() < 0.85){
    // mostly use real device data
    var dev = devices[addrs[Math.floor(Math.random()*addrs.length)]];
    var options = [dev.address];
    if(dev.name && dev.name !== "Unknown") options.push(dev.name);
    if(dev.rssi != null) options.push("RSSI:" + dev.rssi + "dBm");
    if(dev.manufacturer_data) options.push(dev.manufacturer_data.substring(0,20));
    if(dev.est_distance != null && dev.est_distance !== "" && !isNaN(dev.est_distance)) options.push("~" + Number(dev.est_distance).toFixed(1) + "m");
    if(dev.service_uuids) options.push(dev.service_uuids.substring(0,22));
    text = options[Math.floor(Math.random()*options.length)];
  } else {
    // filler hex strings and BLE terms
    var fillers = ["ADV_IND","SCAN_RSP","LL_DATA","ATT_MTU","SMP_PAIR",
      "0x"+Math.floor(Math.random()*0xFFFF).toString(16).toUpperCase().padStart(4,"0"),
      Math.floor(Math.random()*0xFFFFFF).toString(16).toUpperCase().padStart(6,"0")+":"+
      Math.floor(Math.random()*0xFFFFFF).toString(16).toUpperCase().padStart(6,"0")];
    text = fillers[Math.floor(Math.random()*fillers.length)];
  }
  // position: scattered across the full radar canvas, avoid dead center
  var x, y, attempts = 0;
  do {
    x = 40*dpr + Math.random()*(W - 80*dpr);
    y = 30*dpr + Math.random()*(H - 60*dpr);
    attempts++;
  } while(attempts < 5 && Math.abs(x-W/2)<60*dpr && Math.abs(y-H/2)<40*dpr);

  ghosts.push({
    text: text,
    x: x, y: y,
    born: Date.now(),
    lifespan: 2000 + Math.random()*3000, // 2-5 seconds
    flickerRate: 80 + Math.random()*200, // ms between flicker toggles
    fontSize: Math.floor(9 + Math.random()*3)*dpr, // 9-11px
    angle: (Math.random()-0.5)*0.12 // slight random tilt
  });
}

function drawGhosts(W, H, dpr){
  var now = Date.now();
  // spawn new ghosts
  if(now - lastGhostSpawn > GHOST_SPAWN_INTERVAL && ghosts.length < GHOST_MAX){
    spawnGhost(W, H, dpr);
    lastGhostSpawn = now;
  }
  // draw and cull
  for(var gi = ghosts.length-1; gi >= 0; gi--){
    var g = ghosts[gi];
    var age = now - g.born;
    if(age > g.lifespan){ ghosts.splice(gi,1); continue; }
    var progress = age / g.lifespan;
    // envelope: fade in (0-15%), sustain with flicker (15-80%), fade out (80-100%)
    var envelope;
    if(progress < 0.15) envelope = progress / 0.15;
    else if(progress > 0.80) envelope = (1 - progress) / 0.20;
    else envelope = 1;
    // flicker: time-based on/off toggling (frame-rate independent)
    var flickerOn = Math.sin(age / g.flickerRate * Math.PI) > -0.3;
    var flickerCycle = Math.floor(age / g.flickerRate);
    if(!flickerOn && progress > 0.15 && progress < 0.80){
      // occasional hard flicker off (deterministic per cycle)
      if((flickerCycle * 7 + g.born) % 13 === 0) continue;
    }
    // occasional glitch: time-based flash (every ~3s per ghost, not random per frame)
    var glitch = (age % 3000) < 50;
    var alpha = glitch ? 0.18 : Math.max(0, envelope * 0.09 * (flickerOn ? 1 : 0.2));
    if(alpha < 0.005) continue;

    rCtx.save();
    rCtx.translate(g.x, g.y);
    rCtx.rotate(g.angle);
    rCtx.font = g.fontSize + "px monospace";
    rCtx.fillStyle = "rgba(0,255,65," + alpha.toFixed(3) + ")";
    rCtx.fillText(g.text, 0, 0);
    // scanline effect: thin horizontal line through the text
    if(glitch){
      rCtx.fillStyle = "rgba(0,255,65,0.06)";
      rCtx.fillRect(-2*dpr, -g.fontSize*0.3, rCtx.measureText(g.text).width+4*dpr, 1*dpr);
    }
    rCtx.restore();
  }
}

function drawRadar(ts){
  var dpr = window.devicePixelRatio||1;
  var W = rCanvas.width, H = rCanvas.height;
  var cx = W/2, cy = H/2;
  var maxR = Math.min(cx, cy)*0.9;

  rCtx.clearRect(0,0,W,H);

  // ── flickering ghost MAC addresses in background ──
  drawGhosts(W, H, dpr);

  // ── subtle grid lines (crosshair) ──
  rCtx.strokeStyle = "rgba(0,255,65,0.06)";
  rCtx.lineWidth = 1*dpr;
  rCtx.beginPath(); rCtx.moveTo(cx,cy-maxR); rCtx.lineTo(cx,cy+maxR); rCtx.stroke();
  rCtx.beginPath(); rCtx.moveTo(cx-maxR,cy); rCtx.lineTo(cx+maxR,cy); rCtx.stroke();
  // diagonal crosshairs
  var d45 = maxR*0.707;
  rCtx.beginPath(); rCtx.moveTo(cx-d45,cy-d45); rCtx.lineTo(cx+d45,cy+d45); rCtx.stroke();
  rCtx.beginPath(); rCtx.moveTo(cx+d45,cy-d45); rCtx.lineTo(cx-d45,cy+d45); rCtx.stroke();

  // ── distance rings with glow ──
  for(var ri=0;ri<RINGS.length;ri++){
    var r = (Math.log(RINGS[ri]+1)/Math.log(MAX_RING+1))*maxR;
    // outer glow
    rCtx.beginPath();
    rCtx.arc(cx,cy,r,0,Math.PI*2);
    rCtx.strokeStyle = "rgba(0,255,65,0.08)";
    rCtx.lineWidth = 3*dpr;
    rCtx.stroke();
    // crisp ring
    rCtx.beginPath();
    rCtx.arc(cx,cy,r,0,Math.PI*2);
    rCtx.strokeStyle = "rgba(0,255,65,0.2)";
    rCtx.lineWidth = 1*dpr;
    rCtx.stroke();
    // labels at top and right
    rCtx.fillStyle = "rgba(0,255,65,0.45)";
    rCtx.font = (10*dpr)+"px monospace";
    rCtx.fillText(RINGS[ri]+"m", cx+r+4*dpr, cy-4*dpr);
    rCtx.fillText(RINGS[ri]+"m", cx+4*dpr, cy-r-4*dpr);
  }

  // ── outer ring decorative tick marks ──
  rCtx.strokeStyle = "rgba(0,255,65,0.15)";
  rCtx.lineWidth = 1*dpr;
  for(var deg=0; deg<360; deg+=10){
    var a = deg*Math.PI/180;
    var inner = deg%30===0 ? maxR*0.92 : maxR*0.96;
    rCtx.beginPath();
    rCtx.moveTo(cx+Math.cos(a)*inner, cy+Math.sin(a)*inner);
    rCtx.lineTo(cx+Math.cos(a)*maxR, cy+Math.sin(a)*maxR);
    rCtx.stroke();
  }
  // degree labels at 30° intervals
  rCtx.fillStyle = "rgba(0,255,65,0.2)";
  rCtx.font = (8*dpr)+"px monospace";
  for(var deg2=0; deg2<360; deg2+=30){
    var a2 = deg2*Math.PI/180;
    var lx = cx+Math.cos(a2)*(maxR+12*dpr);
    var ly = cy+Math.sin(a2)*(maxR+12*dpr);
    rCtx.fillText(deg2+"\u00B0", lx-10*dpr, ly+4*dpr);
  }

  // ── sweep with multi-layer trail ──
  sweepAngle = ((ts % SWEEP_PERIOD)/SWEEP_PERIOD)*Math.PI*2;
  if(rCtx.createConicGradient){
    // wide dim trail
    var trailLen1 = Math.PI*0.6;
    var grad1 = rCtx.createConicGradient(sweepAngle - trailLen1, cx, cy);
    grad1.addColorStop(0, "rgba(0,255,65,0)");
    grad1.addColorStop(0.7, "rgba(0,255,65,0.03)");
    grad1.addColorStop(1, "rgba(0,255,65,0.08)");
    rCtx.beginPath(); rCtx.moveTo(cx,cy);
    rCtx.arc(cx,cy,maxR, sweepAngle-trailLen1, sweepAngle);
    rCtx.closePath(); rCtx.fillStyle = grad1; rCtx.fill();
    // narrow bright trail
    var trailLen2 = Math.PI*0.25;
    var grad2 = rCtx.createConicGradient(sweepAngle - trailLen2, cx, cy);
    grad2.addColorStop(0, "rgba(0,255,65,0)");
    grad2.addColorStop(0.5, "rgba(0,255,65,0.06)");
    grad2.addColorStop(1, "rgba(0,255,65,0.22)");
    rCtx.beginPath(); rCtx.moveTo(cx,cy);
    rCtx.arc(cx,cy,maxR, sweepAngle-trailLen2, sweepAngle);
    rCtx.closePath(); rCtx.fillStyle = grad2; rCtx.fill();
  } else {
    // fallback for older browsers without createConicGradient
    rCtx.beginPath(); rCtx.moveTo(cx,cy);
    rCtx.arc(cx,cy,maxR, sweepAngle-Math.PI*0.4, sweepAngle);
    rCtx.closePath(); rCtx.fillStyle = "rgba(0,255,65,0.08)"; rCtx.fill();
  }

  // ── sweep line with glow ──
  var sx = cx+Math.cos(sweepAngle)*maxR, sy = cy+Math.sin(sweepAngle)*maxR;
  // glow layer
  rCtx.beginPath(); rCtx.moveTo(cx,cy); rCtx.lineTo(sx,sy);
  rCtx.strokeStyle = "rgba(0,255,65,0.25)";
  rCtx.lineWidth = 6*dpr;
  rCtx.stroke();
  // main line
  rCtx.beginPath(); rCtx.moveTo(cx,cy); rCtx.lineTo(sx,sy);
  rCtx.strokeStyle = "rgba(0,255,65,0.85)";
  rCtx.lineWidth = 2*dpr;
  rCtx.stroke();
  // bright tip
  rCtx.beginPath(); rCtx.arc(sx,sy,3*dpr,0,Math.PI*2);
  rCtx.fillStyle = "#00ff41"; rCtx.fill();

  // ── HUD corner brackets ──
  var cb = 20*dpr, co = 8*dpr;
  rCtx.strokeStyle = "rgba(0,255,65,0.3)";
  rCtx.lineWidth = 2*dpr;
  // top-left
  rCtx.beginPath(); rCtx.moveTo(co,co+cb); rCtx.lineTo(co,co); rCtx.lineTo(co+cb,co); rCtx.stroke();
  // top-right
  rCtx.beginPath(); rCtx.moveTo(W-co-cb,co); rCtx.lineTo(W-co,co); rCtx.lineTo(W-co,co+cb); rCtx.stroke();
  // bottom-left
  rCtx.beginPath(); rCtx.moveTo(co,H-co-cb); rCtx.lineTo(co,H-co); rCtx.lineTo(co+cb,H-co); rCtx.stroke();
  // bottom-right
  rCtx.beginPath(); rCtx.moveTo(W-co-cb,H-co); rCtx.lineTo(W-co,H-co); rCtx.lineTo(W-co,H-co-cb); rCtx.stroke();

  // ── centre marker with pulsing ring ──
  var cPulse = 1 + 0.15*Math.sin(ts/500);
  rCtx.beginPath(); rCtx.arc(cx,cy,8*dpr*cPulse,0,Math.PI*2);
  rCtx.strokeStyle = "rgba(0,255,65,0.3)";
  rCtx.lineWidth = 1*dpr; rCtx.stroke();
  rCtx.beginPath(); rCtx.arc(cx,cy,3*dpr,0,Math.PI*2);
  rCtx.fillStyle = "#00ff41"; rCtx.fill();
  rCtx.font = "bold "+(10*dpr)+"px monospace";
  rCtx.fillStyle = "#00ff41";
  rCtx.fillText("YOU",cx+10*dpr,cy+4*dpr);

  // ── ping ripples (expand outward when new device detected) ──
  var now = Date.now();
  for(var pi=pingRipples.length-1; pi>=0; pi--){
    var p = pingRipples[pi];
    var age = now - p.born;
    if(age > 1200){ pingRipples.splice(pi,1); continue; }
    var progress = age/1200;
    var pr = p.r + (p.maxR - p.r)*progress;
    var pa = (1-progress)*0.4;
    rCtx.beginPath(); rCtx.arc(p.cx,p.cy,pr,0,Math.PI*2);
    rCtx.strokeStyle = hexToRgba(p.color, pa);
    rCtx.lineWidth = 2*dpr; rCtx.stroke();
  }

  // ── particle trails ──
  drawParticles(dpr);

  // ── device dots ──
  var addrs = Object.keys(devices);
  for(var i=0;i<addrs.length;i++){
    var dev = devices[addrs[i]];
    var angle = (hashAddr(dev.address)%3600)/3600*Math.PI*2;
    var dist = dev.est_distance;
    var r2 = distToRadius(dist, maxR);
    // small radius jitter to separate colliding dots
    var jitter = ((hashAddr2(dev.address)%100)-50)/50 * 8 * dpr;
    r2 = Math.max(4*dpr, Math.min(r2 + jitter, maxR));
    var dx = cx + Math.cos(angle)*r2;
    var dy = cy + Math.sin(angle)*r2;
    // spawn particles if device moved
    if(dev._rx !== undefined){
      var moveDist = Math.sqrt((dx-dev._rx)*(dx-dev._rx)+(dy-dev._ry)*(dy-dev._ry));
      if(moveDist > 3*dpr){
        spawnParticles(dev._rx, dev._ry, colorFromRssiOrDist(dev), 3);
      }
    }
    dev._rx = dx; dev._ry = dy;

    var col = colorFromRssiOrDist(dev);
    var baseSize = 4*dpr;
    var age2 = now - (dev._updateTs||0);
    var pulse = age2 < 1500 ? 1 + 0.6*(1 - age2/1500) : 1;
    if(hoveredAddr === dev.address) pulse = Math.max(pulse, 1.6);
    var sz = baseSize * pulse;

    // outer glow ring
    rCtx.beginPath(); rCtx.arc(dx,dy,sz+6*dpr,0,Math.PI*2);
    rCtx.fillStyle = hexToRgba(col,0.06); rCtx.fill();
    // inner glow
    rCtx.beginPath(); rCtx.arc(dx,dy,sz+3*dpr,0,Math.PI*2);
    rCtx.fillStyle = hexToRgba(col,0.15); rCtx.fill();
    // core dot
    rCtx.beginPath(); rCtx.arc(dx,dy,sz,0,Math.PI*2);
    rCtx.fillStyle = col; rCtx.fill();
    // bright center
    rCtx.beginPath(); rCtx.arc(dx,dy,sz*0.4,0,Math.PI*2);
    rCtx.fillStyle = hexToRgba("#ffffff",0.5); rCtx.fill();

    // connecting line from center to dot (very faint)
    rCtx.beginPath(); rCtx.moveTo(cx,cy); rCtx.lineTo(dx,dy);
    rCtx.strokeStyle = hexToRgba(col,0.07);
    rCtx.lineWidth = 1*dpr; rCtx.stroke();

    // label
    if(pulse > 1.3 || hoveredAddr === dev.address){
      rCtx.fillStyle = "#e0e0e0";
      rCtx.font = (9*dpr)+"px monospace";
      var lbl = dev.name && dev.name !== "Unknown" ? dev.name.substring(0,14) : dev.address.substring(0,8);
      rCtx.fillText(lbl, dx+sz+6*dpr, dy+3*dpr);
      // show distance under label
      if(dist!=null && dist!==""){
        rCtx.fillStyle = hexToRgba(col,0.7);
        rCtx.font = (8*dpr)+"px monospace";
        rCtx.fillText("~"+Number(dist).toFixed(1)+"m", dx+sz+6*dpr, dy+14*dpr);
      }
    }
  }

  // ── HUD readouts in corners ──
  var devCount = Object.keys(devices).length;
  rCtx.fillStyle = "rgba(0,255,65,0.35)";
  rCtx.font = (9*dpr)+"px monospace";
  rCtx.fillText("DEVICES: "+devCount, co+4*dpr, co+cb+14*dpr);
  rCtx.fillText("RANGE: "+MAX_RING+"m", W-co-70*dpr, co+cb+14*dpr);

  requestAnimationFrame(drawRadar);
}

// spawn a ping ripple when a new device is detected or updated
function spawnPing(dev, cx, cy, maxR){
  var angle = (hashAddr(dev.address)%3600)/3600*Math.PI*2;
  var dist = dev.est_distance;
  var r2 = distToRadius(dist, maxR);
  var dpr = window.devicePixelRatio||1;
  pingRipples.push({
    cx: cx + Math.cos(angle)*r2,
    cy: cy + Math.sin(angle)*r2,
    r: 4*dpr, maxR: 25*dpr,
    color: colorFromRssiOrDist(dev),
    born: Date.now()
  });
}

requestAnimationFrame(drawRadar);

/* ── radar hit test for tooltip ─────────────────────────── */
rCanvas.addEventListener("mousemove", function(e){
  var rect = rCanvas.getBoundingClientRect();
  var dpr = window.devicePixelRatio||1;
  var mx = (e.clientX - rect.left)*dpr;
  var my = (e.clientY - rect.top)*dpr;
  var hit = null;
  var addrs = Object.keys(devices);
  for(var i=0;i<addrs.length;i++){
    var d = devices[addrs[i]];
    if(d._rx===undefined) continue;
    var dx=d._rx-mx, dy=d._ry-my;
    if(Math.sqrt(dx*dx+dy*dy) < 12*dpr){ hit=d; break; }
  }
  if(hit){
    hoveredAddr = hit.address;
    showTooltip(hit, e.clientX, e.clientY);
  } else {
    hoveredAddr = null;
    hideTooltip();
  }
});
rCanvas.addEventListener("mouseleave", function(){
  hoveredAddr = null;
  hideTooltip();
});

/* ================================================================
   Leaflet Map
   ================================================================ */
var map = null;
var scannerMarker = null;
var devMarkers = {};

function initMap(){
  if(map) return;
  map = L.map("map",{zoomControl:true}).setView([0,0],16);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",{
    attribution:'&copy; OpenStreetMap',maxZoom:19
  }).addTo(map);
}

function updateScannerPos(lat, lon){
  if(!map) initMap();
  var ll = [lat,lon];
  if(!scannerMarker){
    scannerMarker = L.circleMarker(ll,{radius:8,color:"#2196f3",
      fillColor:"#2196f3",fillOpacity:0.7,weight:2}).addTo(map);
    scannerMarker.bindPopup("Scanner position");
    map.setView(ll, 17);
  } else {
    scannerMarker.setLatLng(ll);
    map.setView(ll);
  }
}

function updateDevMarker(dev){
  var gps = dev.best_gps;
  if(!gps || !gps.lat || !gps.lon) return;
  if(!map) initMap();
  var ll = [gps.lat, gps.lon];
  var col = colorFromRssiOrDist(dev);
  if(devMarkers[dev.address]){
    devMarkers[dev.address].setLatLng(ll);
    devMarkers[dev.address].setStyle({color:col,fillColor:col});
  } else {
    var m = L.circleMarker(ll,{radius:6,color:col,fillColor:col,
      fillOpacity:0.8,weight:1}).addTo(map);
    m.bindPopup("<b>"+esc(dev.name||"Unknown")+"</b><br>"+esc(dev.address));
    devMarkers[dev.address] = m;
  }
}

function showMap(){
  var mw = document.getElementById("map-wrap");
  if(!mw.classList.contains("hidden")) return;
  mw.classList.remove("hidden");
  document.getElementById("radar-wrap").classList.remove("full");
  resizeCanvas();
  if(map) setTimeout(function(){ map.invalidateSize(); },100);
}

/* ================================================================
   Device List (right panel) + Pinned Panel (left)
   ================================================================ */
var dlScroll = document.getElementById("dl-scroll");
var dlEntries = {}; // address -> DOM element
var STALE_TIMEOUT = 600000; // 10 minutes — prune devices not seen for this long
var dlPendingUpdate = false;
var dlLastOrder = ""; // track sort order to avoid unnecessary reorder

function sigClass(d){
  var dist = d.est_distance;
  if(dist!=null&&dist!==""&&dist>0){
    if(dist<5) return "sig-close";
    if(dist<=15) return "sig-medium";
    return "sig-far";
  }
  // fallback to RSSI
  var rssi = d.rssi;
  if(rssi==null) return "sig-unknown";
  if(rssi >= -60) return "sig-close";
  if(rssi >= -80) return "sig-medium";
  return "sig-far";
}

function sigBarColor(d){
  var dist = d.est_distance;
  if(dist!=null&&dist!==""&&dist>0){
    if(dist<5) return "sig-green";
    if(dist<=15) return "sig-yellow";
    return "sig-red";
  }
  // fallback to RSSI
  var rssi = d.rssi;
  if(rssi==null) return "sig-none";
  if(rssi >= -60) return "sig-green";
  if(rssi >= -80) return "sig-yellow";
  return "sig-red";
}

// RSSI history for pinned devices (for trend detection + sparklines)
var rssiHistory = {}; // address -> [{rssi, ts}]
var RSSI_HISTORY_MAX = 30;

function recordRssi(addr, rssi){
  if(rssi==null) return;
  if(!rssiHistory[addr]) rssiHistory[addr] = [];
  rssiHistory[addr].push({rssi:rssi, ts:Date.now()});
  if(rssiHistory[addr].length > RSSI_HISTORY_MAX)
    rssiHistory[addr].shift();
}

function rssiTrend(addr){
  var hist = rssiHistory[addr];
  if(!hist || hist.length < 3) return "steady";
  // compare average of last 3 vs previous entries
  var recent = 0, older = 0, rc = 0, oc = 0;
  for(var i=hist.length-1;i>=0;i--){
    if(rc<3){recent+=hist[i].rssi;rc++;}
    else{older+=hist[i].rssi;oc++;}
  }
  if(oc===0) return "steady";
  var avgRecent = recent/rc, avgOlder = older/oc;
  var diff = avgRecent - avgOlder;
  if(diff > 3) return "closer";
  if(diff < -3) return "farther";
  return "steady";
}

function drawSparkline(canvas, addr, colorHex){
  var hist = rssiHistory[addr];
  if(!hist || hist.length < 2) return;
  var ctx = canvas.getContext("2d");
  var W = canvas.width, H = canvas.height;
  ctx.clearRect(0,0,W,H);
  // find range
  var minR = -100, maxR = -30;
  var pts = hist.slice(-20);
  var step = W / (pts.length - 1);
  // gradient fill under line
  var grad = ctx.createLinearGradient(0,0,0,H);
  grad.addColorStop(0, hexToRgba(colorHex, 0.25));
  grad.addColorStop(1, hexToRgba(colorHex, 0.02));
  ctx.beginPath();
  ctx.moveTo(0, H);
  for(var i=0;i<pts.length;i++){
    var x = i * step;
    var y = H - ((pts[i].rssi - minR) / (maxR - minR)) * H;
    y = Math.max(2, Math.min(H-2, y));
    if(i===0) ctx.lineTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.lineTo(W, H);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();
  // draw line
  ctx.beginPath();
  for(var j=0;j<pts.length;j++){
    var lx = j * step;
    var ly = H - ((pts[j].rssi - minR) / (maxR - minR)) * H;
    ly = Math.max(2, Math.min(H-2, ly));
    if(j===0) ctx.moveTo(lx, ly);
    else ctx.lineTo(lx, ly);
  }
  ctx.strokeStyle = colorHex;
  ctx.lineWidth = 1.5;
  ctx.stroke();
  // latest point dot
  var lastX = (pts.length-1) * step;
  var lastY = H - ((pts[pts.length-1].rssi - minR) / (maxR - minR)) * H;
  lastY = Math.max(2, Math.min(H-2, lastY));
  ctx.beginPath();
  ctx.arc(lastX, lastY, 2.5, 0, Math.PI*2);
  ctx.fillStyle = colorHex;
  ctx.fill();
}

// prune stale devices not seen for STALE_TIMEOUT
function pruneStaleDevices(){
  var now = Date.now();
  var addrs = Object.keys(devices);
  for(var i=0;i<addrs.length;i++){
    var addr = addrs[i];
    var d = devices[addr];
    if(now - (d._updateTs||0) > STALE_TIMEOUT && !pinnedAddrs[addr]){
      delete devices[addr];
      // remove DOM entry
      if(dlEntries[addr]){
        if(dlEntries[addr].parentNode) dlEntries[addr].parentNode.removeChild(dlEntries[addr]);
        delete dlEntries[addr];
      }
      // remove map marker
      if(devMarkers[addr]){
        if(map) map.removeLayer(devMarkers[addr]);
        delete devMarkers[addr];
      }
    }
  }
}
// run prune every 30s
setInterval(function(){ pruneStaleDevices(); updateDeviceListNow(); }, 30000);

function updateDeviceList(){
  // throttle: batch updates, run at most once per 500ms
  if(dlPendingUpdate) return;
  dlPendingUpdate = true;
  setTimeout(function(){ dlPendingUpdate=false; updateDeviceListNow(); }, 500);
}

function updateDeviceListNow(){
  var list = Object.values(devices);
  list.sort(function(a,b){
    var va = a.rssi!=null ? a.rssi : -999;
    var vb = b.rssi!=null ? b.rssi : -999;
    return vb - va;
  });
  // build new order key to check if reorder is needed
  var orderKey = "";
  for(var i=0;i<list.length;i++){
    var d = list[i];
    var el = dlEntries[d.address];
    if(!el){
      el = document.createElement("div");
      el.className = "dev-entry";
      el.setAttribute("data-addr", d.address);
      el.innerHTML = '<div><span class="de-addr"></span><span class="de-pin"></span></div>'
        +'<div class="de-name"></div>'
        +'<div class="de-meta"><span class="de-rssi"></span><span class="de-dist"></span></div>'
        +'<div class="signal-bar-wrap"><div class="signal-bar"></div></div>';
      el.addEventListener("click", (function(addr){
        return function(){ togglePin(addr); };
      })(d.address));
      el.addEventListener("mouseenter", (function(addr){
        return function(e){ hoveredAddr=addr; var dd=devices[addr]; if(dd) showTooltip(dd,e.clientX,e.clientY); };
      })(d.address));
      el.addEventListener("mousemove", function(e){
        positionTooltip(document.getElementById("tooltip"),e.clientX,e.clientY);
      });
      el.addEventListener("mouseleave", function(){
        hoveredAddr=null; hideTooltip();
      });
      dlEntries[d.address] = el;
    }
    el.querySelector(".de-addr").textContent = d.address;
    el.querySelector(".de-name").textContent = d.name&&d.name!=="Unknown" ? d.name : "";
    var rssiEl = el.querySelector(".de-rssi");
    rssiEl.textContent = d.rssi!=null ? d.rssi+" dBm" : "";
    rssiEl.style.color = colorFromRssiOrDist(d);
    var distVal = d.est_distance;
    var distStr = (distVal!=null&&distVal!==""&&!isNaN(distVal)) ? "~"+Number(distVal).toFixed(1)+"m" : "";
    el.querySelector(".de-dist").textContent = distStr;
    el.querySelector(".de-pin").textContent = pinnedAddrs[d.address] ? " [pinned]" : "";
    // signal bar: width proportional to RSSI (-100=0%, -30=100%)
    var bar = el.querySelector(".signal-bar");
    var pct = d.rssi!=null ? Math.max(0,Math.min(100,((d.rssi+100)/70)*100)) : 0;
    bar.style.width = pct + "%";
    bar.className = "signal-bar " + sigBarColor(d);
    el.className = "dev-entry " + sigClass(d) + (pinnedAddrs[d.address] ? " pinned" : "");
    if(!el.parentNode) dlScroll.appendChild(el);
    orderKey += d.address + ",";
  }
  // only reorder DOM if sort order changed
  if(orderKey !== dlLastOrder){
    dlLastOrder = orderKey;
    for(var j=0;j<list.length;j++){
      dlScroll.appendChild(dlEntries[list[j].address]);
    }
  }
  document.querySelector("#device-list .dl-header").textContent = "Detected ("+list.length+")";
}

function togglePin(addr){
  if(pinnedAddrs[addr]){
    delete pinnedAddrs[addr];
    delete rssiHistory[addr];
    addLogEntry("PIN", "Unpinned "+addr);
  } else {
    pinnedAddrs[addr] = true;
    // seed RSSI history with current value
    var d = devices[addr];
    if(d && d.rssi!=null) recordRssi(addr, d.rssi);
    addLogEntry("PIN", "Tracking "+addr);
  }
  updateDeviceList();
  updatePinnedPanel();
}

var pinEntries = {}; // address -> DOM element cache
var pinPanelVisible = false;

function updatePinnedPanel(){
  var panel = document.getElementById("pinned-panel");
  var scroll = document.getElementById("pinned-scroll");
  var addrs = Object.keys(pinnedAddrs);
  var wasVisible = pinPanelVisible;
  if(addrs.length === 0){
    if(pinPanelVisible){
      panel.classList.remove("visible");
      pinPanelVisible = false;
      // remove all cached pin entries
      var old = Object.keys(pinEntries);
      for(var oi=0;oi<old.length;oi++){
        if(pinEntries[old[oi]].parentNode) scroll.removeChild(pinEntries[old[oi]]);
        delete pinEntries[old[oi]];
      }
      resizeCanvas(); // only resize on visibility change
    }
    return;
  }
  if(!pinPanelVisible){
    panel.classList.add("visible");
    pinPanelVisible = true;
  }
  // remove entries that are no longer pinned
  var oldPins = Object.keys(pinEntries);
  for(var ri=0;ri<oldPins.length;ri++){
    if(!pinnedAddrs[oldPins[ri]]){
      if(pinEntries[oldPins[ri]].parentNode) scroll.removeChild(pinEntries[oldPins[ri]]);
      delete pinEntries[oldPins[ri]];
    }
  }
  // create or update entries
  for(var i=0;i<addrs.length;i++){
    var addr = addrs[i];
    var d = devices[addr];
    var el = pinEntries[addr];
    if(!el){
      el = document.createElement("div");
      el.className = "pin-entry";
      el.innerHTML = '<div style="flex:1;min-width:0"><div class="pe-addr"></div><div class="pe-name"></div>'
        +'<div class="pe-rssi-big"></div><div class="pe-dist-big"></div>'
        +'<div class="signal-bar-wrap"><div class="signal-bar"></div></div>'
        +'<canvas class="pe-sparkline" width="200" height="28"></canvas>'
        +'<div class="pe-meta"></div></div><span class="pe-close">\u00D7</span>';
      el.querySelector(".pe-close").addEventListener("click", (function(a){
        return function(e){ e.stopPropagation(); togglePin(a); };
      })(addr));
      el.addEventListener("mouseenter", (function(a){
        return function(e){ hoveredAddr=a; var dd=devices[a]; if(dd) showTooltip(dd,e.clientX,e.clientY); };
      })(addr));
      el.addEventListener("mousemove", function(e){
        positionTooltip(document.getElementById("tooltip"),e.clientX,e.clientY);
      });
      el.addEventListener("mouseleave", function(){ hoveredAddr=null; hideTooltip(); });
      pinEntries[addr] = el;
      scroll.appendChild(el);
    }
    // update content
    el.querySelector(".pe-addr").textContent = addr;
    el.querySelector(".pe-name").textContent = (d&&d.name&&d.name!=="Unknown") ? d.name : "";
    // large RSSI display with trend arrow
    var rssiBig = el.querySelector(".pe-rssi-big");
    var trend = rssiTrend(addr);
    var trendArrow = trend==="closer"?" \u25B2":trend==="farther"?" \u25BC":" \u25CF";
    var trendColor = trend==="closer"?"var(--green)":trend==="farther"?"var(--red)":"var(--yellow)";
    var devColor = d ? colorFromRssiOrDist(d) : "#666666";
    rssiBig.innerHTML = (d&&d.rssi!=null) ?
      '<span style="color:'+devColor+'">'+d.rssi+' dBm</span>'
      +'<span class="pe-trend '+trend+'" style="color:'+trendColor+'">'+trendArrow+'</span>' : "";
    // distance display
    var distBig = el.querySelector(".pe-dist-big");
    distBig.textContent = (d&&d.est_distance!=null&&d.est_distance!==""&&!isNaN(d.est_distance)) ? "~"+Number(d.est_distance).toFixed(1)+" m away" : "distance unknown";
    // signal bar
    var pbar = el.querySelector(".signal-bar");
    var ppct = (d&&d.rssi!=null) ? Math.max(0,Math.min(100,((d.rssi+100)/70)*100)) : 0;
    pbar.style.width = ppct + "%";
    pbar.className = "signal-bar " + (d ? sigBarColor(d) : "sig-none");
    // sparkline
    var sparkCanvas = el.querySelector(".pe-sparkline");
    if(sparkCanvas) drawSparkline(sparkCanvas, addr, devColor);
    // meta: trend text
    var trendText = trend==="closer"?"Getting closer":"Getting farther";
    if(trend==="steady") trendText = "Signal steady";
    el.querySelector(".pe-meta").textContent = trendText;
    el.style.borderLeftColor = devColor;
  }
  document.querySelector("#pinned-panel .pp-header").textContent = "Pinned ("+addrs.length+")";
  // only resize on visibility change
  if(!wasVisible && pinPanelVisible) resizeCanvas();
}

/* ================================================================
   Tooltip
   ================================================================ */
function showTooltip(dev, x, y){
  var tip = document.getElementById("tooltip");
  var html = "";
  html += '<span class="lbl">Address:</span> <span class="val">'+esc(dev.address)+'</span><br>';
  html += '<span class="lbl">Name:</span> <span class="val">'+esc(dev.name||"Unknown")+'</span><br>';
  html += '<span class="lbl">RSSI:</span> <span class="val">'+(dev.rssi!=null?dev.rssi+" dBm":"N/A");
  if(dev.avg_rssi!=null) html += ' (avg: '+esc(String(dev.avg_rssi))+' dBm)';
  html += '</span><br>';
  html += '<span class="lbl">TX Power:</span> <span class="val">'+(dev.tx_power!=null?dev.tx_power+' dBm':'N/A')+'</span><br>';
  html += '<span class="lbl">Distance:</span> <span class="val">'+((dev.est_distance!=null&&dev.est_distance!=="")?"~"+Number(dev.est_distance).toFixed(1)+" m":"Unknown")+'</span><br>';
  if(dev.best_gps && dev.best_gps.lat){
    html += '<span class="lbl">Best GPS:</span> <span class="val">'+dev.best_gps.lat.toFixed(6)+', '+dev.best_gps.lon.toFixed(6)+'</span><br>';
  }
  if(dev.manufacturer_data){
    html += '<span class="lbl">Mfr Data:</span> <span class="val">'+esc(dev.manufacturer_data)+'</span><br>';
  }
  if(dev.service_uuids){
    html += '<span class="lbl">Services:</span> <span class="val">'+esc(dev.service_uuids)+'</span><br>';
  }
  html += '<span class="lbl">Seen:</span> <span class="val">'+(dev.times_seen||0)+'x</span>';
  if(dev.resolved===true) html += '<br><span class="val" style="color:var(--green)">IRK RESOLVED</span>';
  tip.innerHTML = html;
  tip.style.display = "block";
  positionTooltip(tip, x, y);
}

function positionTooltip(tip, x, y){
  var tw = tip.offsetWidth, th2 = tip.offsetHeight;
  var wx = window.innerWidth, wy = window.innerHeight;
  var lx = x+14, ly = y+14;
  if(lx+tw > wx-8) lx = x - tw - 14;
  if(ly+th2 > wy-8) ly = y - th2 - 14;
  if(lx<4) lx=4; if(ly<4) ly=4;
  tip.style.left = lx+"px";
  tip.style.top  = ly+"px";
}

function hideTooltip(){
  document.getElementById("tooltip").style.display="none";
}

function esc(s){ if(!s) return ""; var d=document.createElement("div"); d.textContent=s; return d.innerHTML; }

/* ================================================================
   Header / Status
   ================================================================ */
function updateStatus(data){
  if(data.unique_count!=null) document.getElementById("s-unique").textContent = data.unique_count;
  if(data.total_detections!=null) document.getElementById("s-total").textContent = data.total_detections;
  if(data.elapsed!=null){
    var m = Math.floor(data.elapsed/60), s = Math.floor(data.elapsed%60);
    document.getElementById("s-elapsed").textContent = (m<10?"0":"")+m+":"+(s<10?"0":"")+s;
  }
  var dot = document.getElementById("s-dot");
  if(data.scanning===false){ dot.style.color="var(--red)"; }
  else { dot.style.color="var(--green)"; }
}

/* ================================================================
   Audio Pings (Web Audio API)
   ================================================================ */
var audioCtx = null;
var soundEnabled = false;
var soundBtn = document.getElementById("sound-toggle");

soundBtn.addEventListener("click", function(){
  soundEnabled = !soundEnabled;
  soundBtn.textContent = soundEnabled ? "[SND:ON]" : "[SND:OFF]";
  soundBtn.style.color = soundEnabled ? "var(--green)" : "var(--dim)";
  // create AudioContext on first user interaction (browser policy)
  if(soundEnabled && !audioCtx){
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  }
});

function playPing(type){
  if(!soundEnabled || !audioCtx) return;
  try {
    var osc = audioCtx.createOscillator();
    var gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    var now = audioCtx.currentTime;
    if(type === "new"){
      // rising chirp for new device
      osc.type = "sine";
      osc.frequency.setValueAtTime(800, now);
      osc.frequency.linearRampToValueAtTime(1200, now+0.15);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now+0.2);
      osc.start(now);
      osc.stop(now+0.2);
    } else if(type === "pinned"){
      // soft blip for pinned device update
      osc.type = "sine";
      osc.frequency.setValueAtTime(600, now);
      gain.gain.setValueAtTime(0.06, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now+0.1);
      osc.start(now);
      osc.stop(now+0.1);
    }
  } catch(e){}
}

/* ================================================================
   Activity Log
   ================================================================ */
var logContainer = document.getElementById("log-entries");
var LOG_MAX = 60;
var logCount = 0;

function addLogEntry(type, message){
  var now = new Date();
  var ts = (now.getHours()<10?"0":"")+now.getHours()+":"
    +(now.getMinutes()<10?"0":"")+now.getMinutes()+":"
    +(now.getSeconds()<10?"0":"")+now.getSeconds();
  var el = document.createElement("span");
  el.className = "log-entry";
  var typeClass = "lt-new";
  if(type==="LOST") typeClass="lt-lost";
  else if(type==="RSSI") typeClass="lt-rssi";
  else if(type==="IRK") typeClass="lt-irk";
  else if(type==="PIN") typeClass="lt-pin";
  el.innerHTML = '<span class="log-ts">['+ts+']</span> <span class="log-type '+typeClass+'">'+type+'</span> '+esc(message);
  // prepend (newest on left)
  if(logContainer.firstChild) logContainer.insertBefore(el, logContainer.firstChild);
  else logContainer.appendChild(el);
  logCount++;
  // prune oldest
  while(logCount > LOG_MAX && logContainer.lastChild){
    logContainer.removeChild(logContainer.lastChild);
    logCount--;
  }
}

/* ================================================================
   Scan complete overlay
   ================================================================ */
function showOverlay(data){
  var el = document.getElementById("overlay");
  document.getElementById("ov-elapsed").textContent = "Elapsed: "+Number(data.elapsed).toFixed(1)+"s";
  document.getElementById("ov-total").textContent = "Total detections: "+(data.total_detections||0);
  document.getElementById("ov-unique").textContent = "Unique devices: "+(data.unique_devices||0);
  el.style.display = "flex";
}

/* ================================================================
   Socket.IO
   ================================================================ */
var socket = io(window.location.protocol+"//"+window.location.hostname+":"+WSPORT, {transports:["websocket","polling"]});

socket.on("connect", function(){
  // fetch full state on connect
  fetch(window.location.protocol+"//"+window.location.hostname+":"+WSPORT+"/api/state").then(function(r){return r.json();}).then(function(state){
    if(state.devices){
      var addrs = Object.keys(state.devices);
      for(var i=0;i<addrs.length;i++){
        var d = state.devices[addrs[i]];
        d._updateTs = Date.now();
        devices[d.address] = d;
        updateDevMarker(d);
      }
      updateDeviceList();
    }
    if(state.status) updateStatus(state.status);
    if(state.completed){
      updateStatus({scanning:false, elapsed:state.completed.elapsed,
        total_detections:state.completed.total_detections, unique_count:state.completed.unique_devices});
      showOverlay(state.completed);
    }
    if(state.gps && state.gps.lat!=null){
      hasGPS = true;
      scannerGPS = state.gps;
      showMap();
      updateScannerPos(state.gps.lat, state.gps.lon);
    }
  }).catch(function(){});
});

socket.on("device_update", function(d){
  var isNew = !devices[d.address];
  d._updateTs = Date.now();
  devices[d.address] = d;
  // track RSSI history for pinned devices
  if(pinnedAddrs[d.address]){
    recordRssi(d.address, d.rssi);
    if(!isNew) playPing("pinned");
  }
  updateDevMarker(d);
  updateDeviceList();
  if(pinnedAddrs[d.address]) updatePinnedPanel();
  // activity log + effects for new devices
  if(isNew){
    var W = rCanvas.width, H = rCanvas.height;
    var cxr = W/2, cyr = H/2;
    var maxRr = Math.min(cxr,cyr)*0.9;
    spawnPing(d, cxr, cyr, maxRr);
    var label = (d.name && d.name!=="Unknown") ? d.name+" ("+d.address+")" : d.address;
    var distStr = (d.est_distance!=null&&d.est_distance!==""&&!isNaN(d.est_distance)) ? " at ~"+Number(d.est_distance).toFixed(1)+"m" : "";
    addLogEntry("NEW", label + distStr);
    playPing("new");
  }
  if(d.resolved===true && isNew){
    addLogEntry("IRK", "Resolved RPA "+d.address);
  }
});

socket.on("gps_update", function(g){
  if(g && g.lat!=null && g.lon!=null){
    scannerGPS = g;
    if(!hasGPS){ hasGPS=true; showMap(); }
    updateScannerPos(g.lat, g.lon);
  }
});

socket.on("scan_status", function(data){
  updateStatus(data);
});

socket.on("scan_complete", function(data){
  updateStatus({scanning:false, elapsed:data.elapsed,
    total_detections:data.total_detections, unique_count:data.unique_devices});
  showOverlay(data);
});

})();
</script>
""" + r"""{% endraw %}""" + r"""
</body>
</html>
"""


def _timestamp() -> str:
    """Return an ISO 8601 timestamp with timezone offset."""
    return datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")


def _mask_irk(irk_hex: str) -> str:
    """Mask an IRK hex string, showing only the first and last 4 characters."""
    if len(irk_hex) <= 8:
        return irk_hex
    return irk_hex[:4] + "..." + irk_hex[-4:]


class GpsdReader:
    """Lightweight gpsd client that reads GPS fixes over a TCP socket."""

    def __init__(self, host: str = "localhost", port: int = 2947):
        self._host = host
        self._port = port
        self._lock = threading.Lock()
        self._fix: Optional[dict] = None
        self._connected = False
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

    @property
    def fix(self) -> Optional[dict]:
        with self._lock:
            return dict(self._fix) if self._fix else None

    @property
    def connected(self) -> bool:
        with self._lock:
            return self._connected

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        # Close socket to unblock recv() immediately
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _run(self):
        while self._running:
            try:
                self._connect_and_read()
            except (OSError, ConnectionRefusedError, ConnectionResetError):
                pass
            with self._lock:
                self._connected = False
            if self._running:
                time.sleep(_GPS_RECONNECT_DELAY)

    def _connect_and_read(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_GPS_SOCKET_TIMEOUT)
        with self._lock:
            self._sock = sock
        try:
            sock.connect((self._host, self._port))
            with self._lock:
                self._connected = True
            sock.sendall(b'?WATCH={"enable":true,"json":true}\n')
            buf = ""
            while self._running:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                buf += data.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if msg.get("class") == "TPV":
                        lat = msg.get("lat")
                        lon = msg.get("lon")
                        if lat is not None and lon is not None:
                            with self._lock:
                                self._fix = {
                                    "lat": lat,
                                    "lon": lon,
                                    "alt": msg.get("alt"),
                                }
        finally:
            with self._lock:
                self._sock = None
            sock.close()


_GUI_MAX_DEVICES = 1000  # server-side device cache cap


class GuiServer:
    """Flask + SocketIO server for the GUI radar interface."""

    def __init__(self, port: int = 5000):
        if not _HAS_FLASK:
            raise ImportError(
                "GUI requires Flask and flask-socketio. "
                "Install with: pip install flask flask-socketio")
        self._port = port
        self._app = Flask(__name__)
        self._app.config['SECRET_KEY'] = os.urandom(24).hex()
        self._sio = SocketIO(self._app, async_mode='threading', cors_allowed_origins='*')
        self._thread = None
        self._lock = threading.Lock()
        self._devices: Dict[str, dict] = {}
        self._device_ts: Dict[str, float] = {}  # address -> last update time
        self._scan_status: dict = {}
        self._gps_fix: Optional[dict] = None
        self._completed: Optional[dict] = None
        self._setup_routes()

    def _setup_routes(self):
        @self._app.route('/')
        def index():
            return render_template_string(_GUI_HTML, port=self._port)

        @self._app.route('/api/state')
        def state():
            with self._lock:
                devices_copy = json.loads(json.dumps(self._devices))
                status_copy = dict(self._scan_status) if self._scan_status else {}
                gps_copy = dict(self._gps_fix) if self._gps_fix else None
                completed_copy = dict(self._completed) if self._completed else None
            return jsonify({
                'devices': devices_copy,
                'status': status_copy,
                'gps': gps_copy,
                'completed': completed_copy,
            })

    def start(self):
        """Start the Flask server in a background thread."""
        ready = threading.Event()
        result = {'port': -1}

        def _serve():
            for p in range(self._port, self._port + 11):
                # probe the port before committing
                probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    probe.bind(('0.0.0.0', p))
                    probe.close()
                except OSError:
                    probe.close()
                    continue
                # port looks available — attempt to start server
                try:
                    result['port'] = p
                    ready.set()
                    self._sio.run(self._app, host='0.0.0.0', port=p,
                                  allow_unsafe_werkzeug=True,
                                  log_output=False)
                except OSError:
                    # port was grabbed between probe and bind — try next
                    result['port'] = -1
                    continue
                return
            result['port'] = -1
            ready.set()

        self._thread = threading.Thread(target=_serve, daemon=True)
        self._thread.start()

        ready.wait(timeout=5)
        time.sleep(0.3)
        self._port = result['port']
        if self._port == -1:
            raise RuntimeError("Could not find open port for GUI server")

        url = f"http://localhost:{self._port}"
        print(f"  GUI server started at {url}")
        try:
            webbrowser.open(url)
        except Exception:
            print(f"  Could not open browser — navigate to {url}")

    def stop(self):
        """Signal the SocketIO server to shut down."""
        try:
            self._sio.stop()
        except Exception:
            pass

    def _evict_old_devices(self):
        """Remove oldest devices when cache exceeds cap."""
        if len(self._devices) <= _GUI_MAX_DEVICES:
            return
        # evict oldest entries
        sorted_addrs = sorted(self._device_ts, key=self._device_ts.get)
        to_remove = len(self._devices) - _GUI_MAX_DEVICES
        for addr in sorted_addrs[:to_remove]:
            del self._devices[addr]
            del self._device_ts[addr]

    def emit_device(self, data: dict):
        """Push a device update to all connected clients."""
        with self._lock:
            self._devices[data['address']] = data
            self._device_ts[data['address']] = time.time()
            self._evict_old_devices()
        self._sio.emit('device_update', data)

    def emit_gps(self, fix: dict):
        """Push scanner GPS position to all connected clients."""
        with self._lock:
            self._gps_fix = fix
        self._sio.emit('gps_update', fix)

    def emit_status(self, status: dict):
        """Push scan status to all connected clients."""
        with self._lock:
            self._scan_status = status
        self._sio.emit('scan_status', status)

    def emit_complete(self, summary: dict):
        """Push scan complete event and store for reconnecting clients."""
        with self._lock:
            self._completed = summary
        self._sio.emit('scan_complete', summary)


class BLEScanner:
    def __init__(self, target_mac: Optional[str], timeout: float,
                 irks: Optional[List[bytes]] = None,
                 output_format: Optional[str] = None,
                 output_file: Optional[str] = None,
                 verbose: bool = False,
                 quiet: bool = False,
                 min_rssi: Optional[int] = None,
                 rssi_window: int = 1,
                 active: bool = False,
                 environment: str = "free_space",
                 alert_within: Optional[float] = None,
                 log_file: Optional[str] = None,
                 tui: bool = False,
                 adapters: Optional[List[str]] = None,
                 gps: bool = True,
                 ref_rssi: Optional[int] = None,
                 name_filter: Optional[str] = None,
                 gui: bool = False,
                 gui_port: int = 5000):
        self.target_mac = target_mac.upper() if target_mac else None
        self.targeted = target_mac is not None
        self.timeout = timeout
        self.seen_count = 0
        self.unique_devices: Dict[str, int] = {}
        self.running = True
        # IRK mode — supports one or more keys
        self.irks = irks or []
        self.irk_mode = len(self.irks) > 0
        self.resolved_devices: Dict[str, int] = {}
        self.rpa_count = 0
        self.non_rpa_warned: Set[str] = set()
        # Options
        self.verbose = verbose
        self.quiet = quiet
        self.min_rssi = min_rssi
        self.output_format = output_format
        self.output_file = output_file
        self.records: List[dict] = []
        # RSSI averaging
        self.rssi_window = max(1, rssi_window)
        self.rssi_history: Dict[str, deque] = {}
        # Scanning mode
        self.active = active
        # Environment for distance estimation
        self.environment = environment
        # Proximity alerts
        self.alert_within = alert_within
        # Real-time CSV log
        self.log_file = log_file
        self._log_writer = None
        self._log_fh = None
        # Only accumulate records in memory when batch output is requested.
        # For long-running scans without --output, this prevents unbounded
        # memory growth.  Real-time logging (--log) writes directly to disk.
        self._accumulate_records = (output_format is not None)
        # TUI mode
        self.tui = tui
        self.tui_devices: Dict[str, dict] = {}
        self._tui_screen = None
        self._tui_start = 0.0
        # Multi-adapter
        self.adapters = adapters
        # Reference RSSI calibration
        self.ref_rssi = ref_rssi
        # Name filter
        self.name_filter = name_filter
        # GPS
        self._gps = GpsdReader() if gps else None
        self.device_best_gps: Dict[str, dict] = {}
        # Thread safety for detection callback (multi-adapter)
        self._cb_lock = threading.Lock()
        # GUI mode
        self.gui = gui
        self.gui_port = gui_port
        self._gui_server = None

    def _avg_rssi(self, addr: str, rssi: int) -> int:
        """Update RSSI sliding window for a device and return the average."""
        if addr not in self.rssi_history:
            self.rssi_history[addr] = deque(maxlen=self.rssi_window)
        self.rssi_history[addr].append(rssi)
        return round(sum(self.rssi_history[addr]) / len(self.rssi_history[addr]))

    def _build_record(self, device: BLEDevice, adv: AdvertisementData,
                      resolved: Optional[bool] = None,
                      avg_rssi: Optional[int] = None) -> dict:
        """Build a record dict from device/adv data."""
        rssi = adv.rssi
        tx_power = adv.tx_power
        rssi_for_dist = avg_rssi if avg_rssi is not None else rssi
        dist = _estimate_distance(rssi_for_dist, tx_power, self.environment,
                                  ref_rssi=self.ref_rssi)

        mfr_data = ""
        if adv.manufacturer_data:
            parts = []
            for mfr_id, data in adv.manufacturer_data.items():
                parts.append(f"0x{mfr_id:04X}:{data.hex()}")
            mfr_data = "; ".join(parts)

        service_uuids = ", ".join(adv.service_uuids) if adv.service_uuids else ""

        return {
            "timestamp": _timestamp(),
            "address": device.address,
            "name": device.name or "Unknown",
            "rssi": rssi,
            "avg_rssi": avg_rssi if avg_rssi is not None else "",
            "tx_power": tx_power if tx_power is not None else "",
            "est_distance": round(dist, 2) if dist is not None else "",
            "latitude": "",
            "longitude": "",
            "gps_altitude": "",
            "manufacturer_data": mfr_data,
            "service_uuids": service_uuids,
            "resolved": resolved if resolved is not None else "",
        }

    def _record_device(self, device: BLEDevice, adv: AdvertisementData,
                       resolved: Optional[bool] = None,
                       avg_rssi: Optional[int] = None) -> dict:
        """Build a record, optionally append to self.records, write to live
        log, and update TUI state.  Returns the record dict."""
        record = self._build_record(device, adv, resolved=resolved, avg_rssi=avg_rssi)

        # Stamp GPS coordinates on this record
        if self._gps is not None:
            fix = self._gps.fix
            if fix is not None:
                record["latitude"] = fix["lat"]
                record["longitude"] = fix["lon"]
                record["gps_altitude"] = fix["alt"] if fix["alt"] is not None else ""
                # Track per-device best GPS (strongest RSSI = closest proximity)
                addr = (device.address or "").upper()
                current_rssi = adv.rssi
                best = self.device_best_gps.get(addr)
                if best is None or current_rssi > best["rssi"]:
                    self.device_best_gps[addr] = {
                        "lat": fix["lat"],
                        "lon": fix["lon"],
                        "rssi": current_rssi,
                    }

        # Accumulate records only when batch output is needed
        if self._accumulate_records:
            self.records.append(record)

        # Real-time CSV logging
        if self._log_writer is not None:
            self._log_writer.writerow(record)
            self._log_fh.flush()

        # Update TUI device state
        if self.tui:
            addr = (device.address or "").upper()
            self.tui_devices[addr] = {
                "address": device.address,
                "name": device.name or "Unknown",
                "rssi": adv.rssi,
                "avg_rssi": avg_rssi,
                "est_distance": record["est_distance"],
                "times_seen": self.unique_devices.get(addr, 0),
                "last_seen": time.strftime("%H:%M:%S"),
                "resolved": resolved,
            }

        # Update GUI
        if self.gui and self._gui_server is not None:
            addr = (device.address or "").upper()
            best_gps = self.device_best_gps.get(addr)
            self._gui_server.emit_device({
                'address': device.address,
                'name': device.name or 'Unknown',
                'rssi': adv.rssi,
                'avg_rssi': avg_rssi,
                'tx_power': adv.tx_power,
                'est_distance': record['est_distance'],
                'latitude': record.get('latitude', ''),
                'longitude': record.get('longitude', ''),
                'best_gps': best_gps,
                'manufacturer_data': record.get('manufacturer_data', ''),
                'service_uuids': record.get('service_uuids', ''),
                'times_seen': self.unique_devices.get(addr, 0),
                'last_seen': time.strftime('%H:%M:%S'),
                'resolved': resolved,
                'timestamp': record['timestamp'],
            })

        # Proximity alert
        if self.alert_within is not None and record["est_distance"] != "":
            if record["est_distance"] <= self.alert_within:
                if self.tui and self._tui_screen is not None:
                    curses.beep()
                elif not self.quiet and not self.gui:
                    print(f"\a  ** PROXIMITY ALERT ** {device.address} "
                          f"within ~{record['est_distance']:.1f}m "
                          f"(threshold: {self.alert_within}m)")

        return record

    def _print_device(self, device: BLEDevice, adv: AdvertisementData,
                      label: str, resolved: Optional[bool] = None,
                      avg_rssi: Optional[int] = None):
        # Always record for output / log / TUI
        record = self._record_device(device, adv, resolved=resolved, avg_rssi=avg_rssi)

        if self.quiet or self.tui or self.gui:
            return

        rssi = adv.rssi
        dist = record["est_distance"]

        print(f"\n{'='*60}")
        print(f"  {label}")
        print(f"{'='*60}")
        addr_line = f"  Address      : {device.address}"
        if resolved is True:
            addr_line += "  << IRK MATCH >>"
        elif resolved is False:
            addr_line += "  (no match)"
        print(addr_line)
        print(f"  Name         : {device.name or 'Unknown'}")
        if avg_rssi is not None and self.rssi_window > 1:
            addr_key = (device.address or "").upper()
            n_samples = len(self.rssi_history.get(addr_key, []))
            print(f"  RSSI         : {rssi} dBm  (avg: {avg_rssi} dBm over {n_samples} readings)")
        else:
            print(f"  RSSI         : {rssi} dBm")
        tx_power = adv.tx_power
        print(f"  TX Power     : {tx_power if tx_power is not None else 'N/A'} dBm")
        if dist != "":
            print(f"  Est. Distance: ~{dist:.1f} m")
        if adv.local_name and adv.local_name != device.name:
            print(f"  Local Name   : {adv.local_name}")
        if adv.manufacturer_data:
            for mfr_id, data in adv.manufacturer_data.items():
                print(f"  Manufacturer : 0x{mfr_id:04X} -> {data.hex()}")
        if adv.service_uuids:
            print(f"  Services     : {', '.join(adv.service_uuids)}")
        if adv.service_data:
            for uuid, data in adv.service_data.items():
                print(f"  Service Data : {uuid} -> {data.hex()}")
        if adv.platform_data:
            for item in adv.platform_data:
                print(f"  Platform Data: {item}")
        addr_key = (device.address or "").upper()
        best_gps = self.device_best_gps.get(addr_key)
        if best_gps:
            print(f"  Best GPS     : {best_gps['lat']:.6f}, {best_gps['lon']:.6f}")
        print(f"  Timestamp    : {time.strftime('%H:%M:%S')}")
        print(f"{'='*60}")

    def detection_callback(self, device: BLEDevice, adv: AdvertisementData):
        with self._cb_lock:
            self._detection_callback_inner(device, adv)

    def _detection_callback_inner(self, device: BLEDevice,
                                  adv: AdvertisementData):
        addr = (device.address or "").upper()

        # Compute averaged RSSI when windowing is enabled
        avg_rssi = self._avg_rssi(addr, adv.rssi) if self.rssi_window > 1 else None
        effective_rssi = avg_rssi if avg_rssi is not None else adv.rssi

        # RSSI filtering — uses averaged RSSI when available
        if self.min_rssi is not None and effective_rssi < self.min_rssi:
            return

        # Name filtering (case-insensitive substring match)
        if self.name_filter is not None:
            name = device.name or ""
            if self.name_filter.lower() not in name.lower():
                return

        if self.irk_mode:
            self._irk_detection(device, adv, addr, avg_rssi=avg_rssi)
            return

        if self.targeted:
            if self.target_mac not in addr:
                return
            self.seen_count += 1
            self._print_device(device, adv,
                               f"TARGET FOUND  —  detection #{self.seen_count}",
                               avg_rssi=avg_rssi)
        else:
            times_seen = self.unique_devices.get(addr, 0) + 1
            self.unique_devices[addr] = times_seen
            self.seen_count += 1
            self._print_device(device, adv,
                               f"DEVICE #{len(self.unique_devices)}  —  seen {times_seen}x",
                               avg_rssi=avg_rssi)

    def _irk_detection(self, device: BLEDevice, adv: AdvertisementData,
                       addr: str, avg_rssi: Optional[int] = None):
        """Handle a detection in IRK resolution mode."""
        self.seen_count += 1

        is_uuid = len(addr.replace("-", "")) == 32 and ":" not in addr
        if is_uuid:
            if addr not in self.non_rpa_warned:
                self.non_rpa_warned.add(addr)
                if not self.quiet and not self.tui and not self.gui:
                    print(f"  [!] UUID address {addr} — cannot resolve (need real MAC)")
            return

        times_seen = self.unique_devices.get(addr, 0) + 1
        self.unique_devices[addr] = times_seen

        # Check address against all loaded IRKs
        resolved = False
        for irk in self.irks:
            if _resolve_rpa(irk, addr):
                resolved = True
                break

        if resolved:
            self.rpa_count += 1
            det_count = self.resolved_devices.get(addr, 0) + 1
            self.resolved_devices[addr] = det_count
            self._print_device(
                device, adv,
                f"IRK RESOLVED  —  match #{det_count} (addr seen {times_seen}x)",
                resolved=True, avg_rssi=avg_rssi,
            )
        else:
            if self.verbose:
                self._print_device(
                    device, adv,
                    f"IRK NO MATCH  —  addr seen {times_seen}x",
                    resolved=False, avg_rssi=avg_rssi,
                )

    # ------------------------------------------------------------------
    # TUI (curses)
    # ------------------------------------------------------------------

    def _redraw_tui(self, screen):
        """Redraw the TUI live table."""
        try:
            screen.erase()
            h, w = screen.getmaxyx()

            elapsed = time.time() - self._tui_start
            header = (f" btrpa-scan | Devices: {len(self.tui_devices)}"
                      f"  Detections: {self.seen_count}"
                      f"  Elapsed: {elapsed:.0f}s")
            if self.irk_mode:
                header += f"  IRK matches: {self.rpa_count}"
            screen.addnstr(0, 0, header.ljust(w - 1), w - 1,
                           curses.A_BOLD | curses.A_REVERSE)

            settings = f" {'active' if self.active else 'passive'}"
            if self.environment != "free_space":
                settings += f" | env: {self.environment}"
            if self.rssi_window > 1:
                settings += f" | rssi-avg: {self.rssi_window}"
            if self.min_rssi is not None:
                settings += f" | min-rssi: {self.min_rssi}"
            if self.alert_within is not None:
                settings += f" | alert: <{self.alert_within}m"
            if self._gps is not None:
                fix = self._gps.fix
                if fix is not None:
                    settings += f" | GPS: {fix['lat']:.5f},{fix['lon']:.5f}"
                elif self._gps.connected:
                    settings += " | GPS: no fix"
                else:
                    settings += " | GPS: offline"
            screen.addnstr(1, 0, settings, w - 1, curses.A_DIM)

            col_fmt = " {:<19s} {:<16s} {:>5s} {:>5s} {:>7s} {:>5s} {:>8s}"
            col_hdr = col_fmt.format(
                "Address", "Name", "RSSI", "Avg", "Dist", "Seen", "Last")
            screen.addnstr(3, 0, col_hdr, w - 1, curses.A_UNDERLINE)

            sorted_devs = sorted(
                self.tui_devices.values(),
                key=lambda d: d["rssi"], reverse=True,
            )

            row = 4
            for dev in sorted_devs:
                if row >= h - 1:
                    remaining = len(sorted_devs) - (row - 4)
                    screen.addnstr(
                        h - 1, 0,
                        f" ... {remaining} more (resize terminal)", w - 1)
                    break
                avg_str = str(dev["avg_rssi"]) if dev["avg_rssi"] is not None else ""
                dist_str = (f"~{dev['est_distance']:.1f}m"
                            if isinstance(dev["est_distance"], (int, float))
                            else "")
                line = col_fmt.format(
                    (dev["address"] or "")[:18],
                    dev["name"][:15],
                    str(dev["rssi"]), avg_str, dist_str,
                    f"{dev['times_seen']}x",
                    dev["last_seen"],
                )
                attr = curses.A_NORMAL
                if dev.get("resolved") is True:
                    attr = curses.A_BOLD
                if (self.alert_within is not None
                        and isinstance(dev["est_distance"], (int, float))
                        and dev["est_distance"] <= self.alert_within):
                    attr |= curses.A_STANDOUT
                screen.addnstr(row, 0, line, w - 1, attr)
                row += 1

            footer = " Press Ctrl+C to stop"
            if self.log_file:
                footer += f"  |  Logging to {self.log_file}"
            screen.addnstr(h - 1, 0, footer, w - 1, curses.A_DIM)

            screen.refresh()
        except curses.error:
            pass

    # ------------------------------------------------------------------
    # Main scan flow
    # ------------------------------------------------------------------

    async def scan(self):
        # Install signal handlers inside the async context for clean
        # shutdown without the signal-handler / KeyboardInterrupt race.
        loop = asyncio.get_running_loop()
        if platform.system() != "Windows":
            loop.add_signal_handler(signal.SIGINT, self.stop)
            loop.add_signal_handler(signal.SIGTERM, self.stop)

        # Start GPS reader
        if self._gps is not None:
            self._gps.start()
            await asyncio.sleep(_GPS_STARTUP_DELAY)

        elapsed = 0.0
        try:
            # Open real-time CSV log
            if self.log_file:
                self._log_fh = open(self.log_file, "w", newline="")
                self._log_writer = csv.DictWriter(self._log_fh,
                                                  fieldnames=_FIELDNAMES)
                self._log_writer.writeheader()
                self._log_fh.flush()

            # GUI setup
            if self.gui:
                self._gui_server = GuiServer(port=self.gui_port)
                self._gui_server.start()

            # TUI setup
            if self.tui:
                self._tui_screen = curses.initscr()
                curses.noecho()
                curses.cbreak()
                curses.curs_set(0)
                if curses.has_colors():
                    curses.start_color()
                    curses.use_default_colors()

            elapsed = await self._scan_loop()
        finally:
            # TUI cleanup
            if self._tui_screen is not None:
                curses.curs_set(1)
                curses.nocbreak()
                curses.echo()
                curses.endwin()
                self._tui_screen = None

            # Stop GPS reader
            if self._gps is not None:
                self._gps.stop()

            # Close log file (under lock to prevent race with callback)
            with self._cb_lock:
                if self._log_fh is not None:
                    self._log_fh.close()
                    self._log_fh = None
                    self._log_writer = None

            # GUI scan complete + shutdown
            if self.gui and self._gui_server is not None:
                try:
                    self._gui_server.emit_status({
                        'elapsed': round(elapsed, 1),
                        'total_detections': self.seen_count,
                        'unique_count': len(self.unique_devices),
                        'scanning': False,
                    })
                    self._gui_server.emit_complete({
                        'elapsed': round(elapsed, 1),
                        'total_detections': self.seen_count,
                        'unique_devices': len(self.unique_devices),
                    })
                except Exception:
                    pass
            if self._gui_server is not None:
                self._gui_server.stop()

        # Summary and output (printed after TUI is torn down)
        if not self.gui:
            self._print_summary(elapsed)
        self._write_output()

    def _poll_tick(self, start: float):
        """One tick of the scan loop: redraw TUI, emit GUI status/GPS."""
        if self._tui_screen is not None:
            self._redraw_tui(self._tui_screen)
        if self.gui and self._gui_server is not None:
            el = time.time() - start
            self._gui_server.emit_status({
                'elapsed': round(el, 1),
                'total_detections': self.seen_count,
                'unique_count': len(self.unique_devices),
                'scanning': True,
            })
            if self._gps is not None:
                fix = self._gps.fix
                if fix is not None:
                    self._gui_server.emit_gps(fix)

    async def _scan_loop(self) -> float:
        """Run the BLE scanner and return elapsed seconds."""
        if not self.quiet and not self.tui and not self.gui:
            self._print_header()

        scanner_kwargs: dict = {"detection_callback": self.detection_callback}
        if self.active:
            scanner_kwargs["scanning_mode"] = "active"
        if self.irk_mode and platform.system() == "Darwin":
            # Undocumented CoreBluetooth API to retrieve real BD_ADDR
            # instead of CoreBluetooth UUIDs.  May break in future
            # Bleak releases.
            scanner_kwargs["cb"] = {"use_bdaddr": True}

        # Multi-adapter support
        scanners = []
        if self.adapters:
            for adapter in self.adapters:
                kw = {**scanner_kwargs, "adapter": adapter}
                scanners.append(BleakScanner(**kw))
        else:
            scanners.append(BleakScanner(**scanner_kwargs))

        for s in scanners:
            await s.start()

        start = time.time()
        self._tui_start = start
        try:
            if self.timeout == float('inf'):
                while self.running:
                    self._poll_tick(start)
                    await asyncio.sleep(
                        _TUI_REFRESH_INTERVAL if self.tui
                        else _SCAN_POLL_INTERVAL)
            else:
                while self.running and (time.time() - start) < self.timeout:
                    self._poll_tick(start)
                    await asyncio.sleep(_TIMED_SCAN_POLL_INTERVAL)
        except asyncio.CancelledError:
            pass
        finally:
            for s in scanners:
                await s.stop()

        return time.time() - start

    def _print_header(self):
        """Print scan configuration banner."""
        print(_BANNER)
        if self.irk_mode:
            n_irks = len(self.irks)
            if n_irks == 1:
                print("Mode: IRK RESOLUTION — resolving RPAs against provided IRK")
                print(f"  IRK: {_mask_irk(self.irks[0].hex())}")
            else:
                print(f"Mode: IRK RESOLUTION — resolving RPAs against {n_irks} IRKs")
                for i, irk in enumerate(self.irks, 1):
                    print(f"  IRK #{i}: {_mask_irk(irk.hex())}")
            _os = platform.system()
            if _os == "Darwin":
                print("  Note: using undocumented macOS API to retrieve real BT addresses")
            elif _os == "Linux":
                print("  Note: Linux/BlueZ — may require root or CAP_NET_ADMIN")
            elif _os == "Windows":
                print("  Note: Windows/WinRT — real MAC addresses available natively")
        elif self.targeted:
            print(f"Mode: TARGETED — searching for {self.target_mac}")
        else:
            print("Mode: DISCOVER ALL — showing every broadcasting device")
        scan_mode = "active" if self.active else "passive"
        print(f"Scanning: {scan_mode}", end="")
        if self.rssi_window > 1:
            print(f"  |  RSSI averaging: window of {self.rssi_window}")
        else:
            print()
        if self.active and platform.system() == "Darwin":
            print("  Note: CoreBluetooth always scans actively regardless of this flag")
        if self.environment != "free_space":
            print(f"Environment: {self.environment} "
                  f"(n={_ENV_PATH_LOSS[self.environment]})")
        if self.min_rssi is not None:
            print(f"Min RSSI: {self.min_rssi} dBm")
        if self.name_filter is not None:
            print(f"Name filter: \"{self.name_filter}\"")
        if self.alert_within is not None:
            print(f"Proximity alert: within {self.alert_within}m")
        if self.log_file:
            print(f"Live log: {self.log_file}")
        if self.adapters:
            print(f"Adapters: {', '.join(self.adapters)}")
        if self._gps is not None:
            fix = self._gps.fix
            if fix is not None:
                print(f"GPS: connected ({fix['lat']:.6f}, {fix['lon']:.6f})")
            elif self._gps.connected:
                print("GPS: waiting for fix")
            else:
                print("GPS: gpsd not available — continuing without GPS")
        elif self._gps is None:
            print("GPS: disabled")
        if self.timeout == float('inf'):
            print("Running continuously  |  Press Ctrl+C to stop")
        else:
            print(f"Timeout: {self.timeout}s  |  Press Ctrl+C to stop")
        print(f"{'—'*60}")

    def _print_summary(self, elapsed: float):
        """Print scan summary statistics."""
        print(f"\n{'—'*60}")
        print(f"Scan complete — {elapsed:.1f}s elapsed")
        print(f"  Total detections : {self.seen_count}")
        if self.irk_mode:
            print(f"  Unique addresses : {len(self.unique_devices)}")
            print(f"  IRK matches      : {self.rpa_count} detections "
                  f"across {len(self.resolved_devices)} address(es)")
            if self.resolved_devices:
                has_gps = any(a in self.device_best_gps for a in self.resolved_devices)
                print(f"\n  Resolved addresses:")
                if has_gps:
                    print(f"  {'Address':<20} {'Detections':>11}  {'Best GPS'}")
                    print(f"  {'—'*20} {'—'*11}  {'—'*24}")
                else:
                    print(f"  {'Address':<20} {'Detections':>11}")
                    print(f"  {'—'*20} {'—'*11}")
                for addr, count in sorted(self.resolved_devices.items(),
                                          key=lambda x: x[1], reverse=True):
                    line = f"  {addr:<20} {count:>10}x"
                    if has_gps:
                        bg = self.device_best_gps.get(addr)
                        gps_str = f"  {bg['lat']:.6f}, {bg['lon']:.6f}" if bg else ""
                        line += gps_str
                    print(line)
            if not self.resolved_devices:
                print("\n  No addresses resolved — the device may not be "
                      "broadcasting,")
                print("  or the IRK may be incorrect.")
        elif not self.targeted:
            print(f"  Unique devices   : {len(self.unique_devices)}")
            if self.unique_devices:
                has_gps = any(a in self.device_best_gps for a in self.unique_devices)
                if has_gps:
                    print(f"\n  {'Address':<40} {'Seen':>6}  {'Best GPS'}")
                    print(f"  {'—'*40} {'—'*6}  {'—'*24}")
                else:
                    print(f"\n  {'Address':<40} {'Seen':>6}")
                    print(f"  {'—'*40} {'—'*6}")
                for addr, count in sorted(self.unique_devices.items(),
                                          key=lambda x: x[1], reverse=True):
                    line = f"  {addr:<40} {count:>5}x"
                    if has_gps:
                        bg = self.device_best_gps.get(addr)
                        gps_str = f"  {bg['lat']:.6f}, {bg['lon']:.6f}" if bg else ""
                        line += gps_str
                    print(line)

    def _write_output(self):
        """Write batch output file (json / jsonl / csv)."""
        if not self.output_format or not self.records:
            if self.log_file:
                print(f"  Live log written to {self.log_file}")
            return

        filename = self.output_file or f"btrpa-scan-results.{self.output_format}"

        # Support writing to stdout with --output-file -
        if filename == "-":
            if self.output_format == "json":
                sys.stdout.write(json.dumps(self.records, indent=2) + "\n")
            elif self.output_format == "jsonl":
                for record in self.records:
                    sys.stdout.write(json.dumps(record) + "\n")
            elif self.output_format == "csv":
                writer = csv.DictWriter(sys.stdout, fieldnames=_FIELDNAMES)
                writer.writeheader()
                writer.writerows(self.records)
            return

        if self.output_format == "json":
            with open(filename, "w") as f:
                json.dump(self.records, f, indent=2)
        elif self.output_format == "jsonl":
            with open(filename, "w") as f:
                for record in self.records:
                    f.write(json.dumps(record) + "\n")
        elif self.output_format == "csv":
            with open(filename, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=_FIELDNAMES)
                writer.writeheader()
                writer.writerows(self.records)
        print(f"  Results written to {filename}")
        if self.log_file:
            print(f"  Live log written to {self.log_file}")

    def stop(self):
        if not self.tui and not self.gui and self.running:
            print("\nStopping scan...")
        self.running = False


def _estimate_distance(rssi: int, tx_power: Optional[int],
                       env: str = "free_space",
                       ref_rssi: Optional[int] = None) -> Optional[float]:
    """Estimate distance in meters using the log-distance path loss model.

    When *ref_rssi* is provided it is used directly as the expected RSSI at
    the 1-metre reference distance (measured_power), ignoring *tx_power*.
    Otherwise we derive measured_power from *tx_power* by subtracting
    ``_DEFAULT_REF_OFFSET`` (59 dB) — the empirically validated offset used
    by the iBeacon standard that accounts for free-space path loss plus
    typical BLE antenna/enclosure losses.
    """
    if rssi == 0:
        return None
    if ref_rssi is not None:
        measured_power = ref_rssi
    elif tx_power is not None:
        measured_power = tx_power - _DEFAULT_REF_OFFSET
    else:
        return None
    n = _ENV_PATH_LOSS.get(env, 2.0)
    return 10 ** ((measured_power - rssi) / (10 * n))


def _bt_ah(irk: bytes, prand: bytes) -> bytes:
    """Bluetooth Core Spec ah() function (Vol 3, Part H, Section 2.2.2).

    AES-128-ECB(IRK, padding || prand) -> return last 3 bytes.

    Note: ECB mode is mandated by the Bluetooth Core Specification for this
    single-block operation.  It is not a vulnerability — only one 16-byte
    block is ever encrypted, so ECB's lack of diffusion is irrelevant.
    """
    plaintext = b'\x00' * 13 + prand  # 16 bytes: 13 zero-pad + 3-byte prand
    cipher = Cipher(algorithms.AES(irk), modes.ECB())
    enc = cipher.encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return ct[-3:]  # last 3 bytes = hash


def _is_rpa(addr_bytes: bytes) -> bool:
    """Check if a 6-byte address is a Resolvable Private Address.

    RPA has top two bits of the most-significant byte set to 01.
    """
    return len(addr_bytes) == 6 and (addr_bytes[0] >> 6) == 0b01


def _resolve_rpa(irk: bytes, address: str) -> bool:
    """Resolve a MAC address string against an IRK.

    MAC format: AA:BB:CC:DD:EE:FF
    prand = first 3 octets (AA:BB:CC), hash = last 3 octets (DD:EE:FF).
    Returns True if ah(IRK, prand) == hash.
    """
    parts = address.replace("-", ":").split(":")
    if len(parts) != 6:
        return False
    try:
        addr_bytes = bytes(int(b, 16) for b in parts)
    except ValueError:
        return False
    if not _is_rpa(addr_bytes):
        return False
    prand = addr_bytes[:3]
    expected_hash = addr_bytes[3:]
    return _bt_ah(irk, prand) == expected_hash


def _parse_irk(irk_string: str) -> bytes:
    """Parse an IRK from hex string (plain, colon-separated, or 0x-prefixed).

    Returns 16 bytes or raises ValueError.
    """
    s = irk_string.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    s = s.replace(":", "").replace("-", "")
    if len(s) != 32:
        raise ValueError(
            f"IRK must be exactly 16 bytes (32 hex chars), got {len(s)} hex chars")
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise ValueError(f"IRK contains invalid hex characters: {irk_string}")


_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


def main():
    parser = argparse.ArgumentParser(
        description="BLE Scanner — discover all devices or hunt for a specific one"
    )
    parser.add_argument(
        "mac", nargs="?", default=None,
        help="Target MAC address to search for (omit to scan all)"
    )
    parser.add_argument(
        "-a", "--all", action="store_true",
        help="Scan for all broadcasting devices"
    )
    parser.add_argument(
        "--irk", type=str, default=None, metavar="HEX",
        help="Resolve RPAs using this Identity Resolving Key (32 hex chars)"
    )
    parser.add_argument(
        "--irk-file", type=str, default=None, metavar="PATH",
        help="Read IRK(s) from a file (one per line, hex format; "
             "lines starting with # are ignored)"
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=None,
        help="Scan timeout in seconds (default: 30, or infinite for --irk)"
    )

    # Output / logging
    parser.add_argument(
        "--output", choices=["csv", "json", "jsonl"], default=None,
        help="Batch output format written at end of scan"
    )
    parser.add_argument(
        "-o", "--output-file", type=str, default=None, metavar="FILE",
        help="Output file path (default: btrpa-scan-results.<format>; "
             "use - for stdout)"
    )
    parser.add_argument(
        "--log", type=str, default=None, metavar="FILE",
        help="Stream detections to a CSV file in real time"
    )

    # Verbosity
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose mode — show additional details"
    )
    verbosity.add_argument(
        "-q", "--quiet", action="store_true",
        help="Quiet mode — suppress per-device output, show summary only"
    )

    # Signal / detection tuning
    parser.add_argument(
        "--min-rssi", type=int, default=None, metavar="DBM",
        help="Minimum RSSI threshold (e.g. -70) — ignore weaker signals"
    )
    parser.add_argument(
        "--rssi-window", type=int, default=1, metavar="N",
        help="RSSI sliding window size for averaging (e.g. 5-10). "
             "Smooths noisy readings for stable distance estimates "
             "(default: 1 = no averaging)"
    )
    parser.add_argument(
        "--active", action="store_true",
        help="Use active scanning — sends SCAN_REQ to get SCAN_RSP with "
             "additional service UUIDs and names (default: passive)"
    )
    parser.add_argument(
        "--environment", choices=["free_space", "indoor", "outdoor"],
        default="free_space",
        help="Environment preset for distance estimation path-loss exponent: "
             "free_space (n=2.0), outdoor (n=2.2), indoor (n=3.0). "
             "Default: free_space"
    )
    parser.add_argument(
        "--ref-rssi", type=int, default=None, metavar="DBM",
        help="Calibrated RSSI (dBm) measured at 1 metre from the target "
             "device. When set, this value is used directly for distance "
             "estimation instead of deriving it from TX Power. "
             "Also enables distance estimates for devices that don't "
             "advertise TX Power"
    )

    # Filtering
    parser.add_argument(
        "--name-filter", type=str, default=None, metavar="PATTERN",
        help="Filter devices by name (case-insensitive substring match)"
    )

    # Proximity alerts
    parser.add_argument(
        "--alert-within", type=float, default=None, metavar="METERS",
        help="Trigger an audible/visual alert when a device is estimated "
             "within this distance (requires TX Power in advertisements)"
    )

    # TUI
    parser.add_argument(
        "--tui", action="store_true",
        help="Live-updating terminal table instead of scrolling output"
    )

    # GUI
    parser.add_argument(
        "--gui", action="store_true",
        help="Launch web-based radar interface in the browser"
    )
    parser.add_argument(
        "--gui-port", type=int, default=5000, metavar="PORT",
        help="Port for GUI web server (default: 5000)"
    )

    # GPS
    parser.add_argument(
        "--no-gps", action="store_true",
        help="Disable GPS location stamping (GPS is on by default via gpsd)"
    )

    # Multi-adapter (Linux)
    parser.add_argument(
        "--adapters", type=str, default=None, metavar="LIST",
        help="Comma-separated Bluetooth adapter names to scan with "
             "(e.g. hci0,hci1 — Linux only)"
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    if args.output_file and not args.output:
        parser.error("--output-file (-o) requires --output to specify "
                     "the format (csv, json, or jsonl)")

    if args.mac and not _MAC_RE.match(args.mac):
        parser.error(
            f"Invalid MAC address '{args.mac}'. "
            "Expected format: XX:XX:XX:XX:XX:XX (6 colon-separated hex octets)")

    # Determine if any IRK source was provided
    has_irk = bool(args.irk or args.irk_file or os.environ.get("BTRPA_IRK"))

    if has_irk and args.all:
        parser.error("Cannot use IRK with --all")
    if has_irk and args.mac:
        parser.error("Cannot use IRK with a specific MAC address")
    if args.mac and args.all:
        parser.error("Cannot use --all with a specific MAC address")
    if not args.mac and not args.all and not has_irk:
        print(_BANNER)
        parser.print_help()
        sys.exit(0)

    if args.rssi_window < 1:
        parser.error("--rssi-window must be at least 1")

    if args.tui and not _HAS_CURSES:
        parser.error("--tui requires the 'curses' module "
                     "(install 'windows-curses' on Windows)")

    if args.tui and args.quiet:
        parser.error("Cannot use --tui with --quiet")

    if args.gui and not _HAS_FLASK:
        parser.error("--gui requires Flask and flask-socketio. "
                     "Install with: pip install flask flask-socketio")

    if args.gui and args.tui:
        parser.error("Cannot use --gui with --tui")

    if args.gui and args.quiet:
        parser.error("Cannot use --gui with --quiet")

    if args.irk and args.irk_file:
        parser.error("Cannot use --irk and --irk-file together")

    # Parse IRKs (from --irk, --irk-file, or BTRPA_IRK env var)
    irks: List[bytes] = []
    if args.irk:
        try:
            irks.append(_parse_irk(args.irk))
        except ValueError as e:
            parser.error(str(e))
    elif args.irk_file:
        try:
            with open(args.irk_file) as f:
                for line_num, raw_line in enumerate(f, 1):
                    stripped = raw_line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    try:
                        irks.append(_parse_irk(stripped))
                    except ValueError as e:
                        parser.error(f"IRK file line {line_num}: {e}")
        except OSError as e:
            parser.error(f"Cannot read IRK file: {e}")
        if not irks:
            parser.error("IRK file contains no valid keys")
    elif os.environ.get("BTRPA_IRK"):
        try:
            irks.append(_parse_irk(os.environ["BTRPA_IRK"]))
        except ValueError as e:
            parser.error(f"BTRPA_IRK environment variable: {e}")

    # Default timeout
    if args.timeout is not None:
        timeout = args.timeout
    elif irks or args.gui:
        timeout = float('inf')
    else:
        timeout = 30.0

    # Parse adapters
    adapters = None
    if args.adapters:
        adapters = [a.strip() for a in args.adapters.split(",") if a.strip()]
        if not adapters:
            parser.error("--adapters requires at least one adapter name")

    target = args.mac if not args.all and not irks else None
    scanner = BLEScanner(
        target, timeout, irks=irks,
        output_format=args.output,
        output_file=args.output_file,
        verbose=args.verbose,
        quiet=args.quiet,
        min_rssi=args.min_rssi,
        rssi_window=args.rssi_window,
        active=args.active,
        environment=args.environment,
        alert_within=args.alert_within,
        log_file=args.log,
        tui=args.tui,
        adapters=adapters,
        gps=not args.no_gps,
        ref_rssi=args.ref_rssi,
        name_filter=args.name_filter,
        gui=args.gui,
        gui_port=args.gui_port,
    )

    try:
        asyncio.run(scanner.scan())
    except KeyboardInterrupt:
        # Ensure stop() is called so cleanup (summary, output, GUI shutdown)
        # runs properly — covers Windows where add_signal_handler is unavailable.
        scanner.stop()


if __name__ == "__main__":
    main()
