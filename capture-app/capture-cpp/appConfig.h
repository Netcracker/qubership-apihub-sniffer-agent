/*
 * Copyright 2024-2025 NetCracker Technology Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <string>
#include <map>
#include <memory>

class appConfig {
    static std::unique_ptr<appConfig> instance;
    std::map<std::string,std::string> configuration;
    appConfig();
    std::string progName;
    void printUsage();
    std::string optString;
    std::string getOptName(char opt);
public:
    static constexpr const char EMPTY_STR[] = "";
    static constexpr const char OPT_HELP[] = "help";
    static constexpr const char OPT_IFACE[] = "interface";
    static constexpr const char OPT_OUTFL[] = "output";
    static constexpr const char OPT_COUNT[] = "count";
    static constexpr const char OPT_SIZE[] = "snap_len";
    static constexpr const char OPT_TIME[] = "duration";
    static constexpr const char OPT_FILT[] = "filter";
    static constexpr const char OPT_LIST[] = "list";
    static constexpr int NEED_HELP = -1;
    ~appConfig();
    static appConfig& getInstance();
    int parseCmdLine(int argc, char* argv[]);
    inline const std::string& getOpt(const std::string& name) {return configuration[name];};
    inline void setOpt(const std::string& name, const std::string& value) {configuration[name] = value;};
    inline long getOptNum(const std::string& name) {char* pEnd = nullptr; return strtol(configuration[name].c_str(), &pEnd, 10);};
    inline bool hasValueFor(const std::string& name) {return (configuration.count(name)>0); }
};