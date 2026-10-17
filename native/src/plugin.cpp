// Native part of the Pseudo Cpp plugin. Skeleton: proves the build and load path; features come per ticket.
#include "binaryninjaapi.h"

using namespace BinaryNinja;

static void Hello(BinaryView* view)
{
	LogInfo("bncpp_native: %s, %zu functions",
		view->GetFile()->GetFilename().c_str(), view->GetAnalysisFunctionList().size());
}

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		PluginCommand::Register("Pseudo Cpp\\Native\\Hello", "Log the view's file name and function count.", &Hello);
		LogInfo("bncpp_native loaded (core %s, ABI %d)", GetVersionString().c_str(), BN_CURRENT_CORE_ABI_VERSION);
		return true;
	}
}
