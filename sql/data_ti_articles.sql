USE [DB_NAME]
GO

/****** Object:  Table [dbo].[data_ti_articles]    Script Date: 2025-11-07 15:03:15 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[data_ti_articles](
	[pk_id] [int] IDENTITY(1,1) NOT NULL,
	[in_timestamp] [datetime] NULL,
	[source] [varchar](128) NULL,
	[url] [varchar](max) NULL,
	[title] [varchar](max) NULL,
	[summary] [varchar](max) NULL,
	[article] [varchar](max) NULL,
	[score_keywords] [varchar](32) NULL,
	[score_customers] [varchar](32) NULL,
	[cves] [varchar](max) NULL,
	[found_keywords] [varchar](max) NULL,
	[found_customers] [varchar](max) NULL,
	[context_keywords] [varchar](max) NULL,
	[context_customers] [varchar](max) NULL,
	[delivery_timestamp] [datetime] NULL,
 CONSTRAINT [PK__data_ti___1543595E3739DF64] PRIMARY KEY CLUSTERED
(
	[pk_id] ASC
)

WITH (
    PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF,
    IGNORE_DUP_KEY = OFF,
    ALLOW_ROW_LOCKS = ON,
    ALLOW_PAGE_LOCKS = ON,
    OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

EXEC
    sys.sp_addextendedproperty @name=N'Description',
    @value=N'Table stores information about Threat Intel articles used for TI service alerting. ' ,
    @level0type=N'SCHEMA',
    @level0name=N'dbo',
    @level1type=N'TABLE',
    @level1name=N'data_ti_articles'
GO

