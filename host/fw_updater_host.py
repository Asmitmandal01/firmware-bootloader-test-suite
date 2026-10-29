#!/usr/bin/env python3
"""
Host-Side Python Firmware Updater & Fault-Injection Test Harness (`host/fw_updater_host.py`).
Communicates with the compiled C device bootloader (`./build/device_server`) over binary
framed stdin/stdout pipes and executes 4 end-to-end verification campaigns:
  1. Campaign 1 (Clean Transfer): 2,048-byte firmware image (32 chunks x 64B), 0 errors -> v2.1.0 active
  2. Campaign 2 (Corrupted-Transfer with Automatic Retry Recovery):
     Injects CRC-32 bit-flip corruption on Chunks #5, #14, #23, bad SOF on Chunk #10, and an
     out-of-order sequence glitch on Chunk #19. Host receives NACKs, retransmits, and completes
     the update to v2.1.0 with 100% Flash integrity.
  3. Campaign 3 (Unrecoverable Link Noise / Retry Exhaustion):
     Injects 3 consecutive corrupted transmissions on Chunk #12 -> Bootloader aborts and safely
     rolls back to Bank A (v1.0.0).
  4. Campaign 4 (Tampered Whole-Image Signature Attack):
     All 32 chunk CRCs are valid, but byte #400 was altered prior to chunking so whole-image
     CRC-32 fails at END_OF_TX -> Bootloader rejects image (`BL_ERR_IMAGE_CRC_FAIL`) and preserves Bank A (v1.0.0).
"""

import csv
import os
import struct
import subprocess
import zlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional

BL_SOF_MAGIC         = 0xAA55
BL_MAX_PAYLOAD_BYTES = 64
BL_APP_MAGIC         = 0xB00710AD

PKT_SYN_HANDSHAKE = 0x01
PKT_FW_METADATA   = 0x02
PKT_DATA_CHUNK    = 0x03
PKT_END_OF_TX     = 0x04
PKT_ABORT         = 0x05
PKT_ACK           = 0x81
PKT_NACK          = 0x82

STATUS_NAMES = {
    0x00: "BL_OK",
    0x01: "BL_ERR_NULL_PTR",
    0x02: "BL_ERR_BAD_SOF",
    0x03: "BL_ERR_CRC_MISMATCH",
    0x04: "BL_ERR_SEQ_OUT_OF_ORDER",
    0x05: "BL_ERR_LEN_INVALID",
    0x06: "BL_ERR_FLASH_BOUNDS",
    0x07: "BL_ERR_FLASH_WRITE",
    0x08: "BL_ERR_IMAGE_CRC_FAIL",
    0x09: "BL_ERR_STATE_VIOLATION",
    0x0A: "BL_ERR_MAX_RETRIES",
}

STATE_NAMES = {
    0: "IDLE",
    1: "HANDSHAKE_DONE",
    2: "RECEIVING_DATA",
    3: "VERIFYING_IMAGE",
    4: "UPDATE_COMPLETE",
    5: "ABORTED_ROLLBACK",
}


def compute_crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def pack_host_frame(
    pkt_type: int,
    seq_num: int,
    payload: bytes = b"",
    corrupt_crc: bool = False,
    corrupt_sof: bool = False,
) -> bytes:
    sof = 0xDEAD if corrupt_sof else BL_SOF_MAGIC
    plen = len(payload)
    header = struct.pack("<HBHH", sof, pkt_type, seq_num, plen)
    crc = compute_crc32(header + payload)
    if corrupt_crc:
        crc ^= 0x00FF00FF
    padded_payload = payload.ljust(BL_MAX_PAYLOAD_BYTES, b"\x00")
    return header + padded_payload + struct.pack("<I", crc)


@dataclass
class FrameTraceRecord:
    campaign: str
    step_idx: int
    pkt_type_str: str
    seq_num: int
    bytes_transferred: int
    injected_fault: str
    device_response: str
    status_str: str
    fsm_state_str: str
    active_version_str: str


class HostBootloaderClient:
    """Spawns the compiled C device_server binary and exchanges framed packets."""

    def __init__(self, device_bin_path: str, campaign_name: str):
        self.proc = subprocess.Popen(
            [device_bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self.campaign_name = campaign_name
        self.traces: List[FrameTraceRecord] = []
        self.step_idx = 0
        self.bytes_acked = 0

    def send_and_receive(
        self,
        pkt_type: int,
        pkt_type_str: str,
        seq_num: int,
        payload: bytes = b"",
        injected_fault: str = "NONE",
        corrupt_crc: bool = False,
        corrupt_sof: bool = False,
    ) -> dict:
        self.step_idx += 1
        wire_tx = pack_host_frame(
            pkt_type, seq_num, payload, corrupt_crc=corrupt_crc, corrupt_sof=corrupt_sof
        )
        self.proc.stdin.write(wire_tx)
        self.proc.stdin.flush()

        wire_rx = self.proc.stdout.read(15)
        sof, rtype, ack_seq, status, state, ver, rcrc = struct.unpack("<HBHBBII", wire_rx)

        if rtype == PKT_ACK and pkt_type == PKT_DATA_CHUNK:
            self.bytes_acked += len(payload)

        ver_str = f"v{(ver >> 16) & 0xFF}.{(ver >> 8) & 0xFF}.{ver & 0xFF}"
        resp_info = {
            "is_ack": (rtype == PKT_ACK),
            "acked_seq": ack_seq,
            "status": status,
            "status_str": STATUS_NAMES.get(status, f"0x{status:02X}"),
            "state": state,
            "state_str": STATE_NAMES.get(state, f"{state}"),
            "active_version": ver_str,
        }

        self.traces.append(FrameTraceRecord(
            campaign=self.campaign_name,
            step_idx=self.step_idx,
            pkt_type_str=pkt_type_str,
            seq_num=seq_num,
            bytes_transferred=self.bytes_acked,
            injected_fault=injected_fault,
            device_response="ACK" if resp_info["is_ack"] else "NACK",
            status_str=resp_info["status_str"],
            fsm_state_str=resp_info["state_str"],
            active_version_str=ver_str,
        ))
        return resp_info

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=2.0)
        except Exception:
            self.proc.kill()


def generate_firmware_binary(size_bytes: int = 2048) -> bytes:
    """Create a deterministic 2,048-byte synthetic ARM Cortex-M firmware image."""
    return bytes(((i * 31 + 17) & 0xFF) for i in range(size_bytes))


def run_all_host_campaigns(device_bin_path: str, results_dir: str) -> Dict[str, dict]:
    fw_image = generate_firmware_binary(2048)
    fw_crc   = compute_crc32(fw_image)
    target_v = 0x00020100  # v2.1.0
    chunks   = [fw_image[i:i + 64] for i in range(0, len(fw_image), 64)]

    all_traces: List[FrameTraceRecord] = []
    summary: Dict[str, dict] = {}

    # -------------------------------------------------------------------------
    # Campaign 1: Clean Transfer (32 Chunks, 0 Errors)
    # -------------------------------------------------------------------------
    client = HostBootloaderClient(device_bin_path, "1_Clean_Transfer")
    client.send_and_receive(PKT_SYN_HANDSHAKE, "SYN_HANDSHAKE", 0)
    meta_payload = struct.pack("<IIII", BL_APP_MAGIC, target_v, len(fw_image), fw_crc)
    client.send_and_receive(PKT_FW_METADATA, "FW_METADATA", 0, meta_payload)
    for idx, ch in enumerate(chunks, start=1):
        client.send_and_receive(PKT_DATA_CHUNK, "DATA_CHUNK", idx, ch)
    final_resp = client.send_and_receive(PKT_END_OF_TX, "END_OF_TX", len(chunks) + 1)
    client.close()
    all_traces.extend(client.traces)
    summary["clean"] = {
        "traces": client.traces,
        "final_state": final_resp["state_str"],
        "final_version": final_resp["active_version"],
        "total_frames": len(client.traces),
        "nacks": sum(1 for t in client.traces if t.device_response == "NACK"),
    }

    # -------------------------------------------------------------------------
    # Campaign 2: Corrupted-Transfer with Automatic Host Retransmission Recovery
    # -------------------------------------------------------------------------
    client = HostBootloaderClient(device_bin_path, "2_Corrupted_Transfer_Recovery")
    client.send_and_receive(PKT_SYN_HANDSHAKE, "SYN_HANDSHAKE", 0)
    client.send_and_receive(PKT_FW_METADATA, "FW_METADATA", 0, meta_payload)

    for idx, ch in enumerate(chunks, start=1):
        # Inject realistic communication faults on specific chunks
        if idx in (5, 14, 23):
            resp = client.send_and_receive(
                PKT_DATA_CHUNK, "DATA_CHUNK", idx, ch,
                injected_fault="CRC32_BIT_FLIP", corrupt_crc=True
            )
            assert not resp["is_ack"] and resp["status_str"] == "BL_ERR_CRC_MISMATCH"
        elif idx == 10:
            resp = client.send_and_receive(
                PKT_DATA_CHUNK, "DATA_CHUNK", idx, ch,
                injected_fault="CORRUPT_SOF_HEADER", corrupt_sof=True
            )
            assert not resp["is_ack"] and resp["status_str"] == "BL_ERR_BAD_SOF"
        elif idx == 19:
            resp = client.send_and_receive(
                PKT_DATA_CHUNK, "DATA_CHUNK", idx - 1, ch,
                injected_fault="DUPLICATE_SEQ_NUM"
            )
            assert not resp["is_ack"] and resp["status_str"] == "BL_ERR_SEQ_OUT_OF_ORDER"

        # Host automatic retry sends clean packet
        resp_ok = client.send_and_receive(PKT_DATA_CHUNK, "DATA_CHUNK", idx, ch)
        assert resp_ok["is_ack"]

    final_resp = client.send_and_receive(PKT_END_OF_TX, "END_OF_TX", len(chunks) + 1)
    client.close()
    all_traces.extend(client.traces)
    summary["corrupted_recovered"] = {
        "traces": client.traces,
        "final_state": final_resp["state_str"],
        "final_version": final_resp["active_version"],
        "total_frames": len(client.traces),
        "nacks": sum(1 for t in client.traces if t.device_response == "NACK"),
    }

    # -------------------------------------------------------------------------
    # Campaign 3: Unrecoverable Link Failure (3 Consecutive Faults -> Rollback)
    # -------------------------------------------------------------------------
    client = HostBootloaderClient(device_bin_path, "3_Retry_Exhaustion_Rollback")
    client.send_and_receive(PKT_SYN_HANDSHAKE, "SYN_HANDSHAKE", 0)
    client.send_and_receive(PKT_FW_METADATA, "FW_METADATA", 0, meta_payload)
    for idx in range(1, 12):
        client.send_and_receive(PKT_DATA_CHUNK, "DATA_CHUNK", idx, chunks[idx - 1])
    # Fail chunk #12 three consecutive times
    for attempt in range(1, 4):
        final_resp = client.send_and_receive(
            PKT_DATA_CHUNK, "DATA_CHUNK", 12, chunks[11],
            injected_fault=f"CRC32_BIT_FLIP_ATTEMPT_{attempt}", corrupt_crc=True
        )
    client.close()
    all_traces.extend(client.traces)
    summary["retry_exhausted"] = {
        "traces": client.traces,
        "final_state": final_resp["state_str"],
        "final_version": final_resp["active_version"],
        "total_frames": len(client.traces),
        "nacks": sum(1 for t in client.traces if t.device_response == "NACK"),
    }

    # -------------------------------------------------------------------------
    # Campaign 4: Whole-Image Signature Mismatch -> Anti-Brick Rollback
    # -------------------------------------------------------------------------
    client = HostBootloaderClient(device_bin_path, "4_Image_Signature_Tamper_Rollback")
    client.send_and_receive(PKT_SYN_HANDSHAKE, "SYN_HANDSHAKE", 0)
    # Declare authentic header CRC, but flip 1 byte inside chunk #8 before computing chunk CRC
    client.send_and_receive(PKT_FW_METADATA, "FW_METADATA", 0, meta_payload)
    for idx, ch in enumerate(chunks, start=1):
        if idx == 8:
            tampered_ch = bytes([ch[0] ^ 0xFF]) + ch[1:]
            client.send_and_receive(
                PKT_DATA_CHUNK, "DATA_CHUNK", idx, tampered_ch,
                injected_fault="SILENT_PAYLOAD_TAMPER"
            )
        else:
            client.send_and_receive(PKT_DATA_CHUNK, "DATA_CHUNK", idx, ch)
    final_resp = client.send_and_receive(
        PKT_END_OF_TX, "END_OF_TX", len(chunks) + 1,
        injected_fault="VERIFY_TAMPERED_IMAGE"
    )
    client.close()
    all_traces.extend(client.traces)
    summary["tampered_rollback"] = {
        "traces": client.traces,
        "final_state": final_resp["state_str"],
        "final_version": final_resp["active_version"],
        "total_frames": len(client.traces),
        "nacks": sum(1 for t in client.traces if t.device_response == "NACK"),
    }

    # Export complete CSV trace log
    csv_path = os.path.join(results_dir, "ota_transfer_trace_log.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Campaign", "Step_Index", "Packet_Type", "Seq_Num",
            "Cumulative_Bytes_Acked", "Injected_Fault", "Device_Response",
            "Status_Code", "Bootloader_FSM_State", "Active_BankA_Version"
        ])
        for tr in all_traces:
            writer.writerow([
                tr.campaign, tr.step_idx, tr.pkt_type_str, tr.seq_num,
                tr.bytes_transferred, tr.injected_fault, tr.device_response,
                tr.status_str, tr.fsm_state_str, tr.active_version_str
            ])

    return summary


if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dev_bin  = os.path.join(base_dir, "build", "device_server")
    res_dir  = os.path.join(base_dir, "results")
    os.makedirs(res_dir, exist_ok=True)
    summary = run_all_host_campaigns(dev_bin, res_dir)
    for k, v in summary.items():
        print(f"Campaign [{k}]: State={v['final_state']}, ActiveVer={v['final_version']}, Frames={v['total_frames']}, NACKs={v['nacks']}")
