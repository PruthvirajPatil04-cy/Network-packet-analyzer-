with open('app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
new_lines.append('import traceback\n')
new_lines.append('import streamlit as _st_boot\n')
new_lines.append('_st_boot.set_page_config(layout="wide", page_title="Network Packet Analyzer")\n')

# Find where imports end
try_inserted = False
for i, line in enumerate(lines):
    # Remove old set_page_config
    if 'st.set_page_config' in line:
        continue
        
    if line.startswith('st.') and not try_inserted:
        new_lines.append('try:\n')
        try_inserted = True
        
    if try_inserted:
        new_lines.append('    ' + line)
    else:
        new_lines.append(line)

new_lines.append('''
except Exception as _boot_err:
    st.error(f"⚠️ A feature failed to load: {type(_boot_err).__name__}: {_boot_err}")
    with st.expander("Show traceback"):
        st.code(traceback.format_exc())
    st.info("The core dashboard below should still work.")

# Core fallback render — always runs
try:
    st.title("🛡️ Network Packet Analyzer — Live Threat Monitor")
    col1, col2, col3 = st.columns([2, 2, 1.5])
    with col1:
        st.subheader("📥 Incoming Packets")
        pkts = st.session_state.packet_buffer.snapshot() if st.session_state.get("packet_buffer") else []
        if pkts:
            import pandas as pd
            st.dataframe(pd.DataFrame(pkts[-30:]), use_container_width=True, height=400)
        else:
            st.info("Waiting for packets…")
    with col2:
        st.subheader("📊 Server Request Analysis")
        st.info("Charts load when data arrives.")
    with col3:
        st.subheader("🚨 Threat Detection")
        det = st.session_state.get("detector")
        if det and det.alerts:
            for a in det.alerts[-5:]:
                st.error(f"**{a.get('type')}** — {a.get('ip')}\\n\\n{a.get('detail')}")
        else:
            st.success("✅ No intrusions detected")
except Exception:
    pass

# Auto-refresh
import time as _t
_t.sleep(1.5)
st.rerun()
''')

with open('app.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
