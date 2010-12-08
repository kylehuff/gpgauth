#/**********************************************************\ 
# Auto-Generated Plugin Configuration file
# for gpgAuth
#\**********************************************************/

set(PLUGIN_VERSION "1.0.3b")
set(PLUGIN_NAME "gpgAuthPlugin")
set(PLUGIN_PREFIX "GAU")
set(COMPANY_NAME "CURETHEITCH")

# Set MAC drawing methods to 0 and disable the GUI
set(FB_GUI_DISABLED 1)
set(FBMAC_USE_CARBON 0)
set(FBMAC_USE_COCOA 0)
set(FBMAC_USE_QUICKDRAW 0)
set(FBMAC_USE_COREGRAPHICS 0)
set(FBMAC_USE_COREANIMATION 0)

# ActiveX constants:
set(FBTYPELIB_NAME gpgAuthClientLib)
set(FBTYPELIB_DESC "gpgAuthClient ${PLUGIN_VERSION} Type Library")
set(IFBControl_DESC "gpgAuthClient Control Interface")
set(FBControl_DESC "gpgAuthClient Control Class")
set(IFBComJavascriptObject_DESC "gpgAuthClient IComJavascriptObject Interface")
set(FBComJavascriptObject_DESC "gpgAuthClient ComJavascriptObject Class")
set(IFBComEventSource_DESC "gpgAuthClient IFBComEventSource Interface")
set(AXVERSION_NUM "1")

# NOTE: THESE GUIDS *MUST* BE UNIQUE TO YOUR PLUGIN/ACTIVEX CONTROL!  YES, ALL OF THEM!
set(FBTYPELIB_GUID 4d37aeaf-2f01-500e-b173-dd5d6343e4f4)
set(IFBControl_GUID 382e69f9-3d7f-50f3-bc20-5bef69e42e1b)
set(FBControl_GUID a5dd232f-4100-55d2-8e89-08ff1f6a4ba1)
set(IFBComJavascriptObject_GUID 0a938002-3de0-5efe-a56a-35d048753665)
set(FBComJavascriptObject_GUID ad8cfcbb-15b8-57dc-8bc8-7fa15008cadf)
set(IFBComEventSource_GUID c3ef8e07-44f2-52cb-aa52-b63ed8151199)

# these are the pieces that are relevant to using it from Javascript
set(ACTIVEX_PROGID "CURETHEITCH.gpgAuthClient")
set(MOZILLA_PLUGINID "curetheitch.com/gpgAuthClient")

# strings
set(FBSTRING_CompanyName "CURE|THE|ITCH")
set(FBSTRING_FileDescription "gpgAuth web authentication plugin version ${PLUGIN_VERSION} for authentication using GnuPG/PGP")
set(FBSTRING_PLUGIN_VERSION "${PLUGIN_VERSION}")
set(FBSTRING_LegalCopyright "Copyright 2010 CURE|THE|ITCH")
set(FBSTRING_PluginFileName "gpgAuth-v${PLUGIN_VERSION}.dll")
set(FBSTRING_ProductName "gpgAuth")
set(FBSTRING_FileExtents "")
set(FBSTRING_PluginName "gpgAuth")
set(FBSTRING_MIMEType "application/x-gpgauth")

