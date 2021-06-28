# The app_opensips extension
PROJECT("OpenSIPS Diameter Applications" C)

# Find MySQL
FIND_PACKAGE(MySQL REQUIRED)
FIND_PACKAGE(Gcrypt REQUIRED)
INCLUDE_DIRECTORIES(${MySQL_INCLUDE_DIR})

FD_ADD_EXTENSION(app_opensips app_opensips.c avps.c)

TARGET_LINK_LIBRARIES(app_opensips ${GCRYPT_LIBRARY} ${MySQL_LIBRARY} )

####
## INSTALL section ##

INSTALL(TARGETS app_opensips
	LIBRARY DESTINATION ${INSTALL_EXTENSIONS_SUFFIX}
	COMPONENT freeDiameter-debug-tools)

