<?xml version='1.0'?>
<!--
 * $Id$
 *
 * XSL converter script for postgresql databases
 *
 * Copyright (C) 2001-2007 FhG Fokus
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
-->


<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version='1.0'
                xmlns:xi="http://www.w3.org/2001/XInclude"
>

    <xsl:import href="sql.xsl"/>

<!-- specify the table type -->
    <xsl:template name="table.close">
	<xsl:text>)</xsl:text>
	<xsl:if test="type[@db=$db]">
	    <xsl:text> Type=</xsl:text>
	    <xsl:value-of select="normalize-space(type[@db=$db])"/>
	</xsl:if>
	<xsl:text>;&#x0A;&#x0A;</xsl:text>	
    </xsl:template>

    <xsl:template name="column.type">
	<xsl:variable name="type">
	    <xsl:call-template name="get-type"/>
	</xsl:variable>

	<xsl:choose>
	    <xsl:when test="type[@db=$db]">
		<xsl:value-of select="normalize-space(type[@db=$db])"/>
	    </xsl:when>
	    <xsl:when test="$type='char'">
		<xsl:text>SMALLINT</xsl:text>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='short'">
		<xsl:text>SMALLINT</xsl:text>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='int'">
		<xsl:text>INTEGER</xsl:text>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='long'">
		<xsl:text>BIGINT</xsl:text>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='datetime'">
		<xsl:text>TIMESTAMP</xsl:text>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='double'">
		<xsl:text>DOUBLE PRECISION</xsl:text>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='float'">
		<xsl:text>REAL</xsl:text>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='string'">
		<xsl:text>VARCHAR</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='binary'">
		<xsl:text>BYTEA</xsl:text>
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
	<xsl:variable name="column.type">
	    <xsl:call-template name="get-type"/>
	</xsl:variable>
	<xsl:if test="$column.type='datetime'">
	    <xsl:text> WITHOUT TIME ZONE</xsl:text>
	</xsl:if>
        <xsl:if test="autoincrement">
            <xsl:text> SERIAL</xsl:text>
        </xsl:if>
	<!-- PRIMARY KEY column definition -->
        <xsl:if test="primary">
            <xsl:text> PRIMARY KEY</xsl:text>
        </xsl:if>
    </xsl:template>

<!-- copied from sql.xsl because of postgresql different index creation -->
    <xsl:template match="table">
	<xsl:variable name="table.name">
	    <xsl:call-template name="get-name"/>
	</xsl:variable>

	<!-- Create row in version table -->
	<xsl:apply-templates select="version"/>

	<xsl:text>CREATE TABLE </xsl:text>
	<xsl:value-of select="$table.name"/>
	<xsl:text> (&#x0A;</xsl:text>

	<!-- Process all columns -->
	<xsl:apply-templates select="column"/>

	<!-- Process all unique indexes -->
	<xsl:apply-templates select="index[child::unique]"/>

	<!-- Process all primary indexes -->
	<xsl:apply-templates select="index[child::primary]"/>

	<xsl:text>&#x0A;</xsl:text>

	<xsl:call-template name="table.close"/>

	<xsl:for-each select="index[count(child::unique)=0]">
	    <xsl:if test="not(child::primary)">
	        <xsl:call-template name="create_index"/>
	    </xsl:if>
	</xsl:for-each>
    </xsl:template>

    <xsl:template match="index">
	<xsl:variable name="index.name">
	    <xsl:call-template name="get-name"/>
	</xsl:variable>
	<xsl:variable name="table.name">
	    <xsl:call-template name="get-name">
		<xsl:with-param name="select" select="parent::table"/>
	    </xsl:call-template>
	</xsl:variable>

	<xsl:if test="position()=1">
	    <xsl:text>,&#x0A;</xsl:text>
	</xsl:if>
	<xsl:text>    </xsl:text>
	<xsl:if test="not($index.name='')">
	    <xsl:text>CONSTRAINT </xsl:text>
	    <xsl:value-of select="concat($table.name, '_', $index.name, ' ')"/>
	</xsl:if>
	<xsl:if test="unique">
	    <xsl:text>UNIQUE (</xsl:text>
	    <xsl:apply-templates select="colref"/>
	    <xsl:text>)</xsl:text>
	
	    <xsl:if test="not(position()=last())">
		<xsl:text>,</xsl:text>
		<xsl:text>&#x0A;</xsl:text>
	    </xsl:if>
	</xsl:if>
	<!-- PRIMARY KEY standalone definition -->
	<xsl:if test="primary">
	    <xsl:text>PRIMARY KEY</xsl:text>
	    <xsl:text> (</xsl:text>
	    <xsl:apply-templates select="colref"/>
	    <xsl:text>)</xsl:text>
	    <xsl:if test="not(position()=last())">
		<xsl:text>,</xsl:text>
		<xsl:text>&#x0A;</xsl:text>
	    </xsl:if>
	</xsl:if>
    </xsl:template>

    <xsl:template name="create_index">
	<xsl:variable name="index.name">
	    <xsl:call-template name="get-name"/>
	</xsl:variable>
	<xsl:variable name="table.name">
	    <xsl:call-template name="get-name">
		<xsl:with-param name="select" select="parent::table"/>
	    </xsl:call-template>
	</xsl:variable>

	<xsl:text>CREATE </xsl:text>
	<xsl:if test="unique">
	    <xsl:text>UNIQUE </xsl:text>
	</xsl:if>
	<xsl:text>INDEX </xsl:text>
	<xsl:value-of select="concat($table.name, '_', $index.name)"/>
	<xsl:text> ON </xsl:text>
	<xsl:value-of select="$table.name"/>
	<xsl:text> (</xsl:text>
	<xsl:apply-templates select="colref"/>
	<xsl:text>);&#x0A;</xsl:text>

	<xsl:if test="position()=last()">
	    <xsl:text>&#x0A;</xsl:text>
	</xsl:if>
    </xsl:template>

</xsl:stylesheet>
