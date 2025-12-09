import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import paramiko
import threading
import os
import socket

class NetworkConfigApp:
    def __init__(self, root):
        self.root = root
        self.root.title("M500 Network Configuration Utility for 802.1x")
        self.root.geometry("650x900")

        # --- SSH Session State ---
        self.ssh_client = None 

        # --- UI State Variables ---
        self.conn_type_var = tk.StringVar(value="None")
        self.security_var = tk.StringVar()
        self.eap_var = tk.StringVar()
        self.phase2_var = tk.StringVar(value="pap")
        
        # User Inputs
        self.ssid_var = tk.StringVar()
        self.identity_var = tk.StringVar()         
        self.password_var = tk.StringVar()         
        self.anon_identity_var = tk.StringVar()

        # File Paths
        self.path_ca = tk.StringVar()
        self.path_client = tk.StringVar()
        self.path_key = tk.StringVar()

        # --- Validation Triggers ---
        all_vars = [self.conn_type_var, self.security_var, self.eap_var, 
                    self.ssid_var, self.identity_var, self.password_var, 
                    self.path_ca, self.path_client, self.path_key]
        
        for var in all_vars:
            var.trace_add("write", self.check_completeness)

        # ========================================================
        # MAIN LAYOUT
        # ========================================================
        main_container = ttk.Frame(root)
        main_container.pack(fill=tk.BOTH, expand=True)

        self.canvas = tk.Canvas(main_container)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(main_container, orient=tk.VERTICAL, command=self.canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.main_frame = ttk.Frame(self.canvas, padding="20")
        self.canvas_window = self.canvas.create_window((0, 0), window=self.main_frame, anchor="nw")

        self.main_frame.bind("<Configure>", self.on_frame_configure)
        self.canvas.bind("<Configure>", self.on_canvas_configure)
        self.root.bind_all("<MouseWheel>", self._on_mousewheel)

        # ========================================================
        # SECTION 0: TOP CONNECTION BAR (NEW)
        # ========================================================
        self.frame_top = ttk.LabelFrame(self.main_frame, text=" Device Connection ", padding=10)
        self.frame_top.pack(fill=tk.X, pady=(0, 20))

        # Connect Button
        self.btn_connect = ttk.Button(self.frame_top, text="CONNECT TO M500", command=self.start_connection_thread)
        self.btn_connect.pack(side=tk.LEFT, padx=(0, 10))

        # Status Label
        self.lbl_status = ttk.Label(self.frame_top, text="Not Connected", foreground="red", font=("Segoe UI", 10, "bold"))
        self.lbl_status.pack(side=tk.LEFT)

        # ========================================================
        # SECTION 1-3: CONFIGURATION STEPS
        # ========================================================
        self.frame_step1 = ttk.Frame(self.main_frame)
        self.frame_step1.pack(fill=tk.X, pady=(0, 10))

        self.frame_step2 = ttk.Frame(self.main_frame)
        self.frame_step2.pack(fill=tk.X, pady=(0, 10))

        self.frame_step3 = ttk.Frame(self.main_frame)
        self.frame_step3.pack(fill=tk.X, pady=(0, 10))

        self.frame_config = ttk.LabelFrame(self.main_frame, text=" Configuration ", padding=10)
        # Initially hidden, packed dynamically
        self.frame_config.pack_forget()

        self.frame_footer = ttk.Frame(self.main_frame)
        self.frame_footer.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        # --- Content Step 1 ---
        lbl_type = ttk.Label(self.frame_step1, text="1. Select Connection Type:", font=("Segoe UI", 10, "bold"))
        lbl_type.pack(anchor="w", pady=(0, 5))
        r1 = ttk.Radiobutton(self.frame_step1, text="WiFi", variable=self.conn_type_var, 
                             value="WiFi", command=self.show_security_dropdown)
        r2 = ttk.Radiobutton(self.frame_step1, text="Ethernet", variable=self.conn_type_var, 
                             value="Ethernet", command=self.show_security_dropdown)
        r1.pack(side="left", padx=(0, 20))
        r2.pack(side="left")

        # --- Content Step 2 ---
        self.lbl_sec = ttk.Label(self.frame_step2, text="2. Select Security Mode:", font=("Segoe UI", 10, "bold"))
        self.combo_security = ttk.Combobox(self.frame_step2, textvariable=self.security_var, state="readonly")
        self.combo_security['values'] = ("WPA2-Enterprise", "WPA3-Enterprise") 
        self.combo_security.bind("<<ComboboxSelected>>", self.show_eap_dropdown)

        # --- Content Step 3 ---
        self.lbl_eap = ttk.Label(self.frame_step3, text="3. Select EAP Method:", font=("Segoe UI", 10, "bold"))
        self.combo_eap = ttk.Combobox(self.frame_step3, textvariable=self.eap_var, state="readonly")
        self.combo_eap['values'] = ("TLS", "TTLS", "PEAP")
        self.combo_eap.bind("<<ComboboxSelected>>", self.update_ui_visibility)

        # --- Content Config Fields ---
        self.row_ssid = ttk.Frame(self.frame_config)
        ttk.Label(self.row_ssid, text="SSID Name:").pack(anchor="w")
        ttk.Entry(self.row_ssid, textvariable=self.ssid_var).pack(fill=tk.X)
        
        self.row_phase2 = ttk.Frame(self.frame_config)
        ttk.Label(self.row_phase2, text="Phase 2 Authentication:").pack(anchor="w", pady=(5,0))
        self.combo_phase2 = ttk.Combobox(self.row_phase2, textvariable=self.phase2_var, state="readonly")
        self.combo_phase2['values'] = ("pap", "mschapv2")
        self.combo_phase2.current(0)
        self.combo_phase2.pack(fill=tk.X)

        self.row_identity = ttk.Frame(self.frame_config)
        ttk.Label(self.row_identity, text="Identity (Username):").pack(anchor="w", pady=(5,0))
        ttk.Entry(self.row_identity, textvariable=self.identity_var).pack(fill=tk.X)

        self.row_anon = ttk.Frame(self.frame_config)
        ttk.Label(self.row_anon, text="Anonymous Identity:").pack(anchor="w", pady=(5,0))
        ttk.Entry(self.row_anon, textvariable=self.anon_identity_var).pack(fill=tk.X)

        self.row_pass = ttk.Frame(self.frame_config)
        self.lbl_pass = ttk.Label(self.row_pass, text="Password:")
        self.lbl_pass.pack(anchor="w", pady=(5,0))
        ttk.Entry(self.row_pass, textvariable=self.password_var, show="*").pack(fill=tk.X)

        self.files_container = ttk.Frame(self.frame_config)
        self.files_container.pack(fill=tk.X, pady=(10, 0))

        def create_file_row(parent, label_text, var):
            row = ttk.Frame(parent)
            lbl = ttk.Label(row, text=label_text)
            lbl.pack(anchor="w")
            f = ttk.Frame(row)
            f.pack(fill=tk.X, pady=(0, 5))
            entry = ttk.Entry(f, textvariable=var)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            btn = ttk.Button(f, text="...", width=3, command=lambda: self.browse_file(var))
            btn.pack(side=tk.LEFT, padx=(5, 0))
            return row

        self.row_ca = create_file_row(self.files_container, "CA Certificate (ca.pem):", self.path_ca)
        self.row_client = create_file_row(self.files_container, "Client Certificate (client.pem):", self.path_client)
        self.row_key = create_file_row(self.files_container, "Private Key (client.key):", self.path_key)

        # --- Footer ---
        self.btn_run = ttk.Button(self.frame_footer, text="RUN CONFIGURATION", command=self.start_configuration_thread)
        
        lbl_log = ttk.Label(self.frame_footer, text="Execution Logs:", font=("Segoe UI", 9, "bold"))
        lbl_log.pack(anchor="w", pady=(10, 0))
        
        self.log_area = scrolledtext.ScrolledText(
            self.frame_footer, height=12, state='disabled',
            bg='black', fg='#00FF00', font=("Consolas", 9), insertbackground='white'
        )
        self.log_area.pack(fill=tk.BOTH, expand=True, pady=(5, 0))

    # ========================================================
    # CONNECTION LOGIC (NEW)
    # ========================================================
    def start_connection_thread(self):
        self.btn_connect.config(state="disabled")
        self.lbl_status.config(text="Connecting...", foreground="orange")
        t = threading.Thread(target=self.connect_to_device)
        t.start()

    def connect_to_device(self):
        hostname = "169.254.0.10"
        username = "m500"
        password = "TrivediLinuxImageforM500-fEb@2021"

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Connect with a timeout
            client.connect(hostname, username=username, password=password, timeout=5, banner_timeout=5)
            
            # If successful
            self.ssh_client = client
            self.update_status(True, f"Connected ({hostname})")
            self.log(f"Successfully connected to {hostname}")

        except Exception as e:
            self.ssh_client = None
            self.update_status(False, "Not Connected")
            self.log(f"Connection Failed: {e}")
            # REQUIRED POPUP
            messagebox.showerror("Connection Error", "Please connect M500 via ethernet to computer")
        
        finally:
            self.btn_connect.config(state="normal")

    def update_status(self, connected, text):
        color = "green" if connected else "red"
        self.lbl_status.config(text=text, foreground=color)

    # ========================================================
    # EXECUTION LOGIC (Updated to use stored client)
    # ========================================================
    def start_configuration_thread(self):
        # 1. Check if connected first
        if self.ssh_client is None:
             messagebox.showerror("Connection Error", "Please connect to the M500 first using the top button.")
             return
             
        # 2. Check if connection is still alive
        if self.ssh_client.get_transport() is None or not self.ssh_client.get_transport().is_active():
            messagebox.showerror("Connection Lost", "Connection dropped. Please reconnect.")
            self.update_status(False, "Not Connected")
            self.ssh_client = None
            return

        self.log_area.config(state='normal')
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state='disabled')
        t = threading.Thread(target=self.run_logic)
        t.start()

    def run_logic(self):
        try:
            conn_type = self.conn_type_var.get()
            method = self.eap_var.get()
            self.log(f"STARTING: {conn_type} | {method}")
            
            # Use stored client
            client = self.ssh_client
            
            ssid = self.ssid_var.get()
            identity = self.identity_var.get()
            password = self.password_var.get()
            
            files = [self.path_ca.get()]
            if method == "TLS":
                files.extend([self.path_client.get(), self.path_key.get()])
                
            rem_map = self.upload_files(client, files)
            ca_rem = rem_map[self.path_ca.get()]

            cmd = ""
            con_name = ""

            # --- BUILD COMMANDS (Same as before) ---
            if method == "TLS":
                cl_rem = rem_map[self.path_client.get()]
                key_rem = rem_map[self.path_key.get()]
                con_name = "wifi-tls" if conn_type == "WiFi" else "eth-tls"
                base = f'sudo nmcli connection add type {conn_type.lower()} ifname {"wlan0" if conn_type=="WiFi" else "eth0"} con-name {con_name} '
                if conn_type == "WiFi": base += f'ssid "{ssid}" wifi-sec.key-mgmt wpa-eap '
                cmd = (f'{base} 802-1x.eap tls 802-1x.identity "{identity}" '
                       f'802-1x.ca-cert "{ca_rem}" 802-1x.client-cert "{cl_rem}" '
                       f'802-1x.private-key "{key_rem}" 802-1x.private-key-password "{password}"')

            elif method == "TTLS":
                phase2 = self.phase2_var.get()
                con_name = f"{'wifi' if conn_type == 'WiFi' else 'eth'}-ttls-{phase2}"
                base = f'sudo nmcli connection add type {conn_type.lower()} ifname {"wlan0" if conn_type=="WiFi" else "eth0"} con-name {con_name} '
                if conn_type == "WiFi": base += f'ssid "{ssid}" wifi-sec.key-mgmt wpa-eap '
                cmd = (f'{base} 802-1x.eap ttls 802-1x.identity "{identity}" '
                       f'802-1x.password "{password}" 802-1x.ca-cert "{ca_rem}" '
                       f'802-1x.phase2-auth {phase2}')
                if self.anon_identity_var.get():
                     cmd += f' 802-1x.anonymous-identity "{self.anon_identity_var.get()}"'

            elif method == "PEAP":
                con_name = f"{'wifi' if conn_type == 'WiFi' else 'eth'}-peap"
                base = f'sudo nmcli connection add type {conn_type.lower()} ifname {"wlan0" if conn_type=="WiFi" else "eth0"} con-name {con_name} '
                if conn_type == "WiFi": base += f'ssid "{ssid}" wifi-sec.key-mgmt wpa-eap '
                cmd = (f'{base} 802-1x.eap peap 802-1x.identity "{identity}" '
                       f'802-1x.password "{password}" 802-1x.ca-cert "{ca_rem}" '
                       f'802-1x.phase2-auth mschapv2')

            # --- EXECUTE ---
            self.run_remote_command(client, "Configuring Network...", cmd)
            self.run_remote_command(client, "Activating...", f"nmcli con up {con_name}")
            
            messagebox.showinfo("Success", "Configuration Applied Successfully!")
            # Note: We do NOT close the client here anymore, to allow further commands

        except Exception as e:
            self.log(f"ERROR: {e}")
            messagebox.showerror("Execution Error", str(e))

    def upload_files(self, client, files_to_upload):
        remote_cert_dir = "/home/m500/certs/"
        sftp = client.open_sftp()
        client.exec_command(f"mkdir -p {remote_cert_dir}")
        remote_paths = {}
        for local_path in files_to_upload:
            if not local_path or not os.path.exists(local_path):
                raise Exception(f"File not found: {local_path}")
            filename = os.path.basename(local_path)
            remote_full_path = remote_cert_dir + filename
            self.log(f"Uploading: {filename}")
            sftp.put(local_path, remote_full_path)
            remote_paths[local_path] = remote_full_path
        sftp.close()
        return remote_paths

    def run_remote_command(self, client, desc, cmd):
        self.log(desc)
        try:
            stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
            exit_status = stdout.channel.recv_exit_status()
            out_data = stdout.read().decode().strip()
            if out_data: self.log(f"OUT: {out_data}")
            if exit_status != 0: self.log(f"EXIT CODE: {exit_status}")
        except Exception as e:
            self.log(f"CMD ERROR: {e}")

    # ========================================================
    # UI VISIBILITY & HELPERS (Same as before)
    # ========================================================
    def show_security_dropdown(self, event=None):
        self.lbl_sec.pack(anchor="w", pady=(0, 5))
        self.combo_security.pack(fill=tk.X)
        self.security_var.set("")
        self.eap_var.set("")
        self.lbl_eap.pack_forget()
        self.combo_eap.pack_forget()
        self.frame_config.pack_forget()
        self.check_completeness()

    def show_eap_dropdown(self, event):
        self.lbl_eap.pack(anchor="w", pady=(0, 5))
        self.combo_eap.pack(fill=tk.X)
        self.eap_var.set("")
        self.frame_config.pack_forget()
        self.check_completeness()

    def update_ui_visibility(self, event=None):
        conn_type = self.conn_type_var.get()
        method = self.eap_var.get()
        if not method or conn_type == "None":
            self.frame_config.pack_forget()
            return
        
        self.frame_config.pack(fill=tk.X, pady=(0, 15), after=self.frame_step3)
        if conn_type == "WiFi": self.row_ssid.pack(fill=tk.X, pady=(0, 5))
        else: self.row_ssid.pack_forget()

        self.row_identity.pack(fill=tk.X, pady=(0, 5))
        
        if method == "TLS":
            self.lbl_pass.config(text="Private Key Password:")
            self.row_pass.pack(fill=tk.X, pady=(0, 5))
            self.row_phase2.pack_forget()
            self.row_anon.pack_forget()
            self.row_ca.pack(fill=tk.X, pady=(5, 0))
            self.row_client.pack(fill=tk.X, pady=(5, 0))
            self.row_key.pack(fill=tk.X, pady=(5, 0))
        elif method == "TTLS":
            self.lbl_pass.config(text="User Password:")
            self.row_pass.pack(fill=tk.X, pady=(0, 5))
            self.row_phase2.pack(fill=tk.X, pady=(0, 5))
            self.row_anon.pack(fill=tk.X, pady=(0, 5))
            self.row_ca.pack(fill=tk.X, pady=(5, 0))
            self.row_client.pack_forget()
            self.row_key.pack_forget()
        elif method == "PEAP":
            self.lbl_pass.config(text="User Password:")
            self.row_pass.pack(fill=tk.X, pady=(0, 5))
            self.row_phase2.pack_forget()
            self.row_anon.pack_forget()
            self.row_ca.pack(fill=tk.X, pady=(5, 0))
            self.row_client.pack_forget()
            self.row_key.pack_forget()
        self.check_completeness()

    def check_completeness(self, *args):
        conn = self.conn_type_var.get()
        sec = self.security_var.get()
        method = self.eap_var.get()
        is_complete = False
        if conn != "None" and sec and method:
            has_identity = bool(self.identity_var.get().strip())
            has_ssid = True
            if conn == "WiFi": has_ssid = bool(self.ssid_var.get().strip())
            if method == "TLS":
                has_pass = bool(self.password_var.get()) 
                has_files = all([self.path_ca.get(), self.path_client.get(), self.path_key.get()])
                if has_identity and has_ssid and has_pass and has_files: is_complete = True
            elif method in ["TTLS", "PEAP"]:
                has_pass = bool(self.password_var.get())
                has_ca = bool(self.path_ca.get())
                if has_identity and has_ssid and has_pass and has_ca: is_complete = True
        if is_complete: self.btn_run.pack(pady=20, fill=tk.X, before=self.log_area)
        else: self.btn_run.pack_forget()

    def on_frame_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas_window, width=event.width)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def browse_file(self, var):
        filepath = filedialog.askopenfilename()
        if filepath: var.set(filepath)

    def log(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, ">> " + message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkConfigApp(root)
    root.mainloop()