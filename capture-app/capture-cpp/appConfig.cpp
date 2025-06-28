// Copyright 2024-2025 NetCracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "appConfig.h"
#include <cstdlib>
#include <cstring>
#include <cctype>
#if defined(_MSC_VER) || defined(__BORLANDC__)
#include "getopt_win32.h"
#define PATH_SEP    '\\'
#else   // defined(_MSC_VER) || defined(__BORLANDC__)
#include <getopt.h>
#define PATH_SEP    '/'
#endif  // defined(_MSC_VER) || defined(__BORLANDC__)

std::unique_ptr<appConfig> appConfig::instance(new appConfig());
static const struct option modOpts[] = {
        { appConfig::OPT_LIST,   no_argument, nullptr,       'l' },
        { appConfig::OPT_HELP,   no_argument, nullptr,       'h' },
        { appConfig::OPT_IFACE,  required_argument, nullptr, 'i' },
        { appConfig::OPT_OUTFL,  required_argument, nullptr, 'o' },
        { appConfig::OPT_COUNT,  required_argument, nullptr, 'c' },
        { appConfig::OPT_SIZE,   required_argument, nullptr, 's' },
        { appConfig::OPT_TIME,   required_argument, nullptr, 'd' },
        { appConfig::OPT_FILT,   required_argument, nullptr, 'f' },
        { nullptr,               no_argument,       nullptr, 0   }
};

appConfig::appConfig() : configuration(),progName(), optString() {
    setOpt(appConfig::OPT_SIZE, "262144");
    setOpt(appConfig::OPT_COUNT, "-1");
    const auto* pOpt = (const option*)&modOpts;
    while (pOpt->name != nullptr && pOpt->val != 0)
    {
        char c[3] = {0};
        c[0] = pOpt->val;
        if (pOpt->has_arg == required_argument)
        {
            c[1] = ':';
            c[2] = '\0';
        }
        else
            c[1] = '\0';
        optString += (c);
        pOpt++;
    }
}

appConfig::~appConfig() {

}

appConfig& appConfig::getInstance()
{
    return *appConfig::instance.get();
}

/**
 * parse classical argc,argv parameters from main to internal storage
 * @param argc program argument count
 * @param argv program argument values
 */
int appConfig::parseCmdLine(int argc, char* argv[])
{
    char* ptr = strrchr(argv[0],PATH_SEP);
    if(ptr!=nullptr)    {
        progName.assign(ptr + 1);
    }
    else {
        progName.assign(argv[0]);
    }
    int opt, longIndex;
    int needHelp = 0;
    const auto* pModOpts = (const struct option*)&modOpts;
    opt = getopt_long(argc, argv, optString.c_str(), pModOpts, &longIndex);
    while (opt != -1 && needHelp==0)
    {
        switch (opt)
        {
            case 'h':
                needHelp = appConfig::NEED_HELP;
                break;
            case 'i':
            case 'o':
            case 's':
            case 'f':
                if (optarg)
                {
                    const std::string& optName = getOptName(opt);
                    if (!optName.empty())
                    {
                        setOpt(optName, optarg);
                    }
                }
                break;
            case 'c':
            case 'd':
                if (optarg)
                {
                    const std::string& optName = getOptName(opt);
                    char* pEnd = nullptr;
                    long lres = strtol(optarg, &pEnd, 10);
                    if(lres>0 || (pEnd != nullptr && strlen(pEnd)>0) )    {
                        if (!optName.empty())
                        {
                            setOpt(optName, optarg);
                        }
                    }
                    else {
                        std::cerr << "Improper value " << lres << "=>'" << pEnd << "' for " << optName << std::endl;
                        needHelp = appConfig::NEED_HELP;
                    }
                }
                break;
            case 'l':
                {
                    const std::string& optName = getOptName(opt);
                    if (!optName.empty())
                    {
                        setOpt(optName, appConfig::EMPTY_STR);
                    }
                }
                break;
            default:
                // if(argv[optind][0] != '-')
                // {
                //     std::string tmp = argv[optind-1];
                //     if(!tmp.empty())
                //     {
                //         tmp = tmp.substr(2);
                //         appConfig::configuration.emplace(tmp,argv[optind]);
                //     }
                // }
                // else
                // {
                //     std::string tmp = argv[optind];
                //     if(!tmp.empty())
                //     {
                //         tmp = tmp.substr(1);
                //         appConfig::configuration.emplace(tmp,argv[optind+1]);
                //     }
                // }
                needHelp = opt;
                break;
        }
        opt = getopt_long(argc, argv, optString.c_str(), pModOpts, &longIndex);
    }
    if (needHelp == 0)
    {
        return EXIT_SUCCESS;
    }
    if (needHelp != appConfig::NEED_HELP)
    {
        // unknown option
        std::cerr << "unknown option '" << char(needHelp) << "'" << std::endl;
    }
    appConfig::printUsage();
    return EXIT_FAILURE;
}

/**
 * returns corresponding option long name by its short name
 * @param opt short name to lookup
 * @return option name or empty string
 */
std::string appConfig::getOptName(char opt)
{
    const auto* pModOpts = (const struct option*)&modOpts;
    while (pModOpts->name != nullptr)
    {
        if (pModOpts->val == opt)
        {
            return {pModOpts->name};
        }
        pModOpts++;
    }
    return appConfig::EMPTY_STR;
}

static std::map<std::string, std::string> helpMap{
        { appConfig::OPT_HELP,   "To see this message" },
        { appConfig::OPT_IFACE,  "Interface to capture packets on" },
        { appConfig::OPT_OUTFL,  "The capture result file" },
        { appConfig::OPT_COUNT,  "Capture packet count limit (no limit by default)" },
        { appConfig::OPT_SIZE,   "Capture buffer length (a.k.a. snap len, 262144 by default)" },
        { appConfig::OPT_TIME,   "Capture duration limit in seconds (no limit by default)" },
        { appConfig::OPT_FILT,   "Filter string" },
        { appConfig::OPT_FILT,   "List interfaces with addresses and exit" },
};

/**
 * prints program usage message
 */
void appConfig::printUsage()
{
    std::cerr << "Usage: " << progName << " [options]" << std::endl;
    const auto* pModOpts = (const struct option*)&modOpts;
    std::cerr << std::endl;
    std::cerr << "Options:" << std::endl;
    while (pModOpts->name != nullptr) {
        if (helpMap.count(pModOpts->name) > 0) {
            int chr = pModOpts->val;
            std::cerr << "    -" << (char)(chr) << ", --" << pModOpts->name;
            if (pModOpts->has_arg & required_argument) {
                std::cerr << " <" << pModOpts->name << ">";
            }
            if (pModOpts->has_arg & optional_argument) {
                std::cerr << " [" << pModOpts->name << "]";
            }
            std::cerr << "    " << helpMap[pModOpts->name] << std::endl;
        }
        pModOpts++;
    }
}
