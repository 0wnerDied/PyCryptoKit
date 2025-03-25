# -*- mode: python ; coding: utf-8 -*-
import os
import shutil
from PyInstaller.utils.hooks import collect_dynamic_libs

block_cipher = None

excluded_qt_modules = [
    'PySide6.QtPdf', 
    'PySide6.QtQuick', 
    'PySide6.QtQml',
    'PySide6.QtNetwork',
    'PySide6.QtSql',
    'PySide6.QtSvg',
    'PySide6.QtTest',
    'PySide6.QtWebEngineCore',
    'PySide6.QtWebEngineWidgets',
    'PySide6.QtWebChannel',
    'PySide6.Qt3DCore',
    'PySide6.Qt3DRender',
    'PySide6.QtMultimedia',
    'PySide6.QtDataVisualization',
    'PySide6.QtCharts',
    'PySide6.QtBluetooth',
    'PySide6.QtConcurrent',
    'PySide6.QtOpenGL',
    'PySide6.QtOpenGLWidgets',
    'PySide6.QtPositioning',
    'PySide6.QtPrintSupport',
    'PySide6.QtRemoteObjects',
    'PySide6.QtScxml',
    'PySide6.QtSensors',
    'PySide6.QtSerialPort',
    'PySide6.QtTextToSpeech',
    'PySide6.QtUiTools',
    'PySide6.QtXml',
]

all_excludes = [
    'matplotlib', 'numpy', 'pandas', 'scipy', 'PyQt5', 'PIL', 'notebook', 'IPython', 
    'tkinter', 'test', 'setuptools', 'email', 'html', 'http', 'pyinstaller',
    'pydoc_data', 'unittest', 'lib2to3', 'pkg_resources',
    'asyncio', 'concurrent', 'ctypes', 'curses', 
    'ensurepip', 'idlelib', 'multiprocessing', 'venv'
] + excluded_qt_modules

a = Analysis(
    ['__main__.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=all_excludes,
    noarchive=False,
    optimize=1,
)

# 排除不需要的Qt插件
excluded_plugins = [
    'qmltooling',
    'designer',
    'sceneparsers',
    'virtualkeyboard',
    'multimedia',
    'webview',
    'audio',
    'sensors',
    'geoservices',
    'texttospeech',
    'webengine',
    '3dinput',
    'renderplugins',
    'sqldrivers',
    'modelio',
]

for plugin in excluded_plugins:
    a.binaries = [x for x in a.binaries if not x[0].startswith(f'PySide6/Qt/plugins/{plugin}')]

a.datas = [x for x in a.datas if not x[0].startswith('PySide6/Qt/translations')]

qt_frameworks_to_exclude = [
    'QtPdf.framework',
    'QtQuick.framework',
    'QtQml.framework',
    'QtNetwork.framework',
    'QtSql.framework',
    'QtSvg.framework',
    'QtTest.framework',
    'QtWebEngineCore.framework',
    'QtWebEngineWidgets.framework',
    'QtWebChannel.framework',
    'Qt3DCore.framework',
    'Qt3DRender.framework',
    'QtMultimedia.framework',
    'QtDataVisualization.framework',
    'QtCharts.framework',
    'QtBluetooth.framework',
    'QtConcurrent.framework',
    'QtOpenGL.framework',
    'QtOpenGLWidgets.framework',
    'QtPositioning.framework',
    'QtPrintSupport.framework',
    'QtRemoteObjects.framework',
    'QtScxml.framework',
    'QtSensors.framework',
    'QtSerialPort.framework',
    'QtTextToSpeech.framework',
    'QtUiTools.framework',
    'QtXml.framework',
]

a.binaries = [x for x in a.binaries if not any(framework in x[0] for framework in qt_frameworks_to_exclude)]

a.datas = [x for x in a.datas if not any(framework in x[0] for framework in qt_frameworks_to_exclude)]

excluded_so_files = [
    'QtPdf.abi3.so',
    'QtQuick.abi3.so',
    'QtQml.abi3.so',
    'QtNetwork.abi3.so',
    'QtSql.abi3.so',
    'QtSvg.abi3.so',
    'QtTest.abi3.so',
    'QtWebEngineCore.abi3.so',
    'QtWebEngineWidgets.abi3.so',
    'QtWebChannel.abi3.so',
    'Qt3DCore.abi3.so',
    'Qt3DRender.abi3.so',
    'QtMultimedia.abi3.so',
    'QtDataVisualization.abi3.so',
    'QtCharts.abi3.so',
    'QtBluetooth.abi3.so',
    'QtConcurrent.abi3.so',
    'QtOpenGL.abi3.so',
    'QtOpenGLWidgets.abi3.so',
    'QtPositioning.abi3.so',
    'QtPrintSupport.abi3.so',
    'QtRemoteObjects.abi3.so',
    'QtScxml.abi3.so',
    'QtSensors.abi3.so',
    'QtSerialPort.abi3.so',
    'QtTextToSpeech.abi3.so',
    'QtUiTools.abi3.so',
    'QtXml.abi3.so',
]

a.binaries = [x for x in a.binaries if not any(so_file in x[0] for so_file in excluded_so_files)]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='PyCryptoKit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_dir='/opt/homebrew/bin/upx',
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch='arm64',
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=True,
    upx=True,
    upx_dir='/opt/homebrew/bin/upx',
    upx_exclude=[],  # 避免压缩加密库
    name='PyCryptoKit',
)

app = BUNDLE(
    coll,
    name='PyCryptoKit.app',
    icon='gui/views/icon/icon.icns',
    bundle_identifier=None,
    info_plist={
        'NSHighResolutionCapable': 'True',
        'CFBundleShortVersionString': '1.0.0',
    },
)

def post_build_cleanup():
    dist_dir = os.path.join('dist', 'PyCryptoKit', '_internal', 'PySide6', 'Qt', 'lib')
    if os.path.exists(dist_dir):
        for framework in qt_frameworks_to_exclude:
            framework_path = os.path.join(dist_dir, framework)
            if os.path.exists(framework_path):
                print(f"删除不需要的框架: {framework_path}")
                shutil.rmtree(framework_path)

if hasattr(BUNDLE, 'post_build_hooks'):
    BUNDLE.post_build_hooks.append(post_build_cleanup)
