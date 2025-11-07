USE [DB_NAME]
GO

/****** Object:  Table [dbo].[data_ti_cves]    Script Date: 2025-11-07 15:03:24 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[data_ti_cves](
	[pk_cve_id] [int] IDENTITY(1,1) NOT NULL,
	[in_timestamp] [datetime] NULL,
	[CVE_ID] [varchar](16) NOT NULL,
	[CVSS] [varchar](32) NULL,
	[severity] [varchar](32) NULL,
 CONSTRAINT [PK__data_ti___72D892AE5872CB0B] PRIMARY KEY CLUSTERED
(
	[pk_cve_id] ASC
)

WITH (
    PAD_INDEX = OFF,
    STATISTICS_NORECOMPUTE = OFF,
    IGNORE_DUP_KEY = OFF,
    ALLOW_ROW_LOCKS = ON,
    ALLOW_PAGE_LOCKS = ON,
    OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

EXEC
    sys.sp_addextendedproperty @name=N'Description',
    @value=N'Table stores CVE details along with CVSS and severity.' ,
    @level0type=N'SCHEMA',
    @level0name=N'dbo',
    @level1type=N'TABLE',
    @level1name=N'data_ti_cves'
GO

