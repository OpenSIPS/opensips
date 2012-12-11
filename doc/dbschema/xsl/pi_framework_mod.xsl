<?xml version='1.0'?>
<!--
 * $Id$
 *
-->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
				version='1.0'
				xmlns:xi="http://www.w3.org/2001/XInclude">

	<xsl:import href="sql.xsl"/>

	<!-- Create the file for the mod in pi_http subdirectory -->
	<xsl:template match="/">
		<xsl:variable name="path" select="concat($dir, concat('/', concat($prefix, 'mod')))"/>
		<xsl:document href="{$path}" method="text" indent="no" omit-xml-declaration="yes">
			<xsl:apply-templates select="/database[1]"/>
		</xsl:document>
	</xsl:template>

	<xsl:template match="table">
		<xsl:variable name="table.name">
			<xsl:call-template name="get-name"/>
		</xsl:variable>
		<xsl:text>&#x9;&lt;!-- </xsl:text>
		<xsl:value-of select="$table.name"/>
		<xsl:text> provisionning --&gt;&#xa;</xsl:text>
		<xsl:text>&#x9;&lt;mod&gt;&lt;mod_name&gt;</xsl:text>
		<xsl:value-of select="$table.name"/>
		<xsl:text>&lt;/mod_name&gt;&#xa;</xsl:text>
		<xsl:text>&#x9;&#x9;&lt;cmd&gt;&lt;cmd_name&gt;show&lt;/cmd_name&gt;&#xa;</xsl:text>
		<xsl:text>&#x9;&#x9;&#x9;&lt;db_table_id&gt;</xsl:text>
		<xsl:value-of select="$table.name"/>
		<xsl:text>&lt;/db_table_id&gt;&#xa;</xsl:text>
		<xsl:text>&#x9;&#x9;&#x9;&lt;cmd_type&gt;DB_QUERY&lt;/cmd_type&gt;&#xa;</xsl:text>
		<xsl:text>&#x9;&#x9;&#x9;&lt;query_cols&gt;&#xa;</xsl:text>
		<xsl:apply-templates select="column"/>
		<xsl:text>&#x9;&#x9;&#x9;&lt;/query_cols&gt;&#xa;</xsl:text>
		<xsl:text>&#x9;&#x9;&lt;/cmd&gt;&#xa;</xsl:text>
		<xsl:text>&#x9;&lt;/mod&gt;&#xa;</xsl:text>
	</xsl:template>

	<xsl:template match="column">
		<xsl:text>&#x9;&#x9;&#x9;&#x9;&lt;col&gt;&lt;field&gt;</xsl:text>
		<xsl:call-template name="get-name"/>
		<xsl:text>&lt;/field&gt;&lt;/col&gt;&#xa;</xsl:text>
	</xsl:template>

</xsl:stylesheet>

