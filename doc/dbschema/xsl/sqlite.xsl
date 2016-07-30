<?xml version='1.0'?>
<!--
 *
 *
 * XSL converter script for mysql databases
 *
 * Copyright (C) 2001-2007 FhG Fokus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */
-->


<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version='1.0'
                xmlns:xi="http://www.w3.org/2001/XInclude"
>

    <xsl:import href="sql.xsl"/>

<!--
    <xsl:template match="database" mode="drop">
	<xsl:apply-templates mode="drop"/>
    </xsl:template>
-->

<!-- specify the table type -->
    <xsl:template name="table.close">
	<xsl:text>)</xsl:text>
	<xsl:text>;&#x0A;&#x0A;</xsl:text>	
    </xsl:template>

    <xsl:template name="column.type">
	<xsl:variable name="type">
	    <xsl:call-template name="get-type"/>
	</xsl:variable>

	<xsl:choose>
			<!--transform bigint primary key autoincrement to integer -->
		<xsl:when test="$type='long' and primary and autoincrement">
		    <xsl:text> INTEGER PRIMARY KEY AUTOINCREMENT </xsl:text>
		</xsl:when>
	    <xsl:when test="type[@db=$db]">
		<xsl:value-of select="normalize-space(type[@db=$db])"/>
	    </xsl:when>
	    <xsl:when test="$type='char'">
		<xsl:text>TINYINT</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='short'">
		<xsl:text>SMALLINT</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='int'">
		<xsl:text>INTEGER</xsl:text>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='long'">
		<xsl:text>BIGINT</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='datetime'">
		<xsl:text>DATETIME</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='double'">
		<xsl:text>DOUBLE</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='float'">
		<xsl:text>FLOAT</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='string'">
		<xsl:text>CHAR</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='binary'">
		<xsl:text>BLOB</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='text'">
		<xsl:text>TEXT</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:call-template name="type-error"/>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>

    <xsl:template name="column.trailing">
	<xsl:variable name="signed">
	    <xsl:call-template name="get-sign"/>
	</xsl:variable>	
	<!-- PRIMARY KEY column definition -->
	<xsl:if test="primary">
	    <xsl:text> PRIMARY KEY</xsl:text>
	</xsl:if>
	<xsl:if test="autoincrement">
	    <xsl:text> AUTOINCREMENT</xsl:text>
	</xsl:if>
    </xsl:template>

	<xsl:template name="get-index-name">
	<xsl:variable name="index.name">
	    <xsl:call-template name="get-name"/>
	</xsl:variable>
	<xsl:variable name="table.name">
	    <xsl:call-template name="get-name">
		<xsl:with-param name="select" select="parent::table"/>
	    </xsl:call-template>
	</xsl:variable>
	<!-- because oracle don't allow index names longer than 30 -->
	<xsl:choose>
	<xsl:when test="not(string-length(concat($table.name, '_', $index.name)) > 30)">
		<xsl:value-of select="concat($table.name, '_', $index.name, ' ')"/>
	</xsl:when>
	<xsl:otherwise>
		<xsl:value-of select="concat('ORA_', $index.name, ' ')"/>
	</xsl:otherwise>
	</xsl:choose>
	</xsl:template>



</xsl:stylesheet>
