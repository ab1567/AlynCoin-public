#include "config.h"

AppConfig& getAppConfig() {
    static AppConfig cfg;
    return cfg;
}
