<?xml version='1.0'?>
<!--
 * $Id$
 *
 * XSL converter script for oracle databases
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
                xmlns:db="http://iptel.org/dbschema/oracle"
>

    <xsl:import href="sql.xsl"/>

    <xsl:template match="database" mode="drop">
	<xsl:apply-templates mode="drop"/>
    </xsl:template>

    <xsl:template name="table.close">
	<xsl:variable name="table.name">
		<xsl:call-template name="get-name"/>
	</xsl:variable>
	<xsl:text>)</xsl:text>
	<xsl:text>;&#x0A;&#x0A;</xsl:text>

	<!-- small hack, as the version table don't have an id field -->
	<xsl:if test="not($table.name='version')">
		<!-- create the autoincrement trigger -->
		<xsl:text>CREATE OR REPLACE TRIGGER </xsl:text>
		<xsl:value-of select="concat($table.name, '_tr&#x0A;')"/>
		<xsl:text>before insert on </xsl:text>
		<xsl:value-of select="$table.name"/>
		<xsl:text> FOR EACH ROW&#x0A;</xsl:text>
		<xsl:text>BEGIN&#x0A;</xsl:text>
		<xsl:text>  auto_id(:NEW.id);&#x0A;</xsl:text>
		<xsl:text>END </xsl:text>
		<xsl:value-of select="concat($table.name, '_tr;&#x0A;')"/>
		<xsl:text>/&#x0A;</xsl:text>
	</xsl:if>
	<xsl:text>BEGIN map2users('</xsl:text>
	<xsl:value-of select="$table.name"/>
	<xsl:text>'); END;&#x0A;</xsl:text>
	<xsl:text>/&#x0A;</xsl:text>
    </xsl:template>

    <xsl:template name="column.type">
	<xsl:variable name="type">
	    <xsl:call-template name="get-type"/>
	</xsl:variable>

	<xsl:choose>
	    <xsl:when test="db:type">
		<xsl:value-of select="normalize-space(db:type)"/>
	    </xsl:when>
	    <xsl:when test="$type='char'">
		<xsl:text>NUMBER(5)</xsl:text>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='short'">
		<xsl:text>NUMBER(5)</xsl:text>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='int'">
		<xsl:text>NUMBER</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='long'">
		<xsl:text>BIGINT</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='datetime'">
		<xsl:text>DATE</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='double'">
		<xsl:text>NUMBER</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='float'">
		<xsl:text>NUMBER</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='string'">
		<xsl:text>VARCHAR2</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='binary'">
		<xsl:text>BLOB</xsl:text>
		<xsl:call-template name="column.size"/>
		<xsl:call-template name="column.trailing"/>
	    </xsl:when>
	    <xsl:when test="$type='text'">
		<xsl:text>CLOB</xsl:text>
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
		<xsl:variable name="table.name">
	    	<xsl:call-template name="get-name">
				<xsl:with-param name="select" select="parent::table"/>
			</xsl:call-template>
		</xsl:variable>
		<xsl:text> PRIMARY KEY</xsl:text>
	</xsl:if>
    </xsl:template>

    <xsl:template match="index">
	<xsl:variable name="index.name">
	    <xsl:call-template name="get-name"/>
	</xsl:variable>

	<xsl:if test="position()=1">
	    <xsl:text>,&#x0A;</xsl:text>
	</xsl:if>
	<xsl:text>    </xsl:text>
	<xsl:if test="unique">
	    <xsl:text>UNIQUE </xsl:text>
	</xsl:if>
	<xsl:text>KEY </xsl:text>
	<xsl:if test="not($index.name='')">
	    <xsl:value-of select="concat($index.name, ' ')"/>
	</xsl:if>
	<xsl:text>(</xsl:text>
	<xsl:apply-templates select="colref"/>
	<xsl:text>)</xsl:text>
	<xsl:if test="not(position()=last())">
	    <xsl:text>,</xsl:text>
	    <xsl:text>&#x0A;</xsl:text>
	</xsl:if>
    </xsl:template>

<!-- copied from sql.xsl because of oracle different index creation -->
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
	    <xsl:value-of select="$index.name"/>
	</xsl:if>
	<xsl:if test="unique">
	    <xsl:text> UNIQUE (</xsl:text>
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
	<xsl:value-of select="$index.name"/>
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
