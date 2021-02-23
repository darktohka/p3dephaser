# -*- mode: python -*-

block_cipher = None

a = Analysis(['p3dephaser/Launcher.py'],
             pathex=[],
             binaries=[],
             datas=[],
             hiddenimports=['PySide2', 'psutil', 'mem_edit'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='P3Dephaser',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=False,
          runtime_tmpdir=None,
          console=False, icon='icon.ico')
app = BUNDLE(exe,
             name='P3Dephaser.app',
             icon='icon.icns',
             bundle_identifier=None)