/**********************************************************\

  Auto-generated FactoryMain.cpp

  This file contains the auto-generated factory methods
  for the gpgAuth project

\**********************************************************/

#include "FactoryDefinitions.h"
#include "gpgAuthPlugin.h"

FB::PluginCore *_getMainPlugin()
{
    return new gpgAuthPlugin();
}

void GlobalPluginInitialize()
{
    gpgAuthPlugin::StaticInitialize();
}

void GlobalPluginDeinitialize()
{
    gpgAuthPlugin::StaticDeinitialize();
}
