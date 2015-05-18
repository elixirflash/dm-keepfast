/* linux/arch/arm/mach-exynos/include/mach/map-exynos4.h
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * EXYNOS4 - Memory map definitions
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#ifndef __ASM_ARCH_MAP_EXYNOS4_H
#define __ASM_ARCH_MAP_EXYNOS4_H __FILE__

#define EXYNOS4_PA_SYSRAM0		0x02025000
#define EXYNOS4_PA_SYSRAM1		0x02020000
#define EXYNOS4_PA_SYSRAM_NS		0x0203F000
#define EXYNOS4_PA_SYSRAM_NS_4212	0x0204F000

#define EXYNOS4_PA_FIMC0		0x11800000
#define EXYNOS4_PA_FIMC1		0x11810000
#define EXYNOS4_PA_FIMC2		0x11820000
#define EXYNOS4_PA_FIMC3		0x11830000

#define EXYNOS4_PA_JPEG			0x11840000

#define EXYNOS4_PA_AUDSS		0x03810000
#define EXYNOS4_PA_I2S0			0x03830000
#define EXYNOS4_PA_I2S1			0xE2100000
#define EXYNOS4_PA_I2S2			0xE2A00000
#define EXYNOS4212_PA_I2S1		0x13960000
#define EXYNOS4212_PA_I2S2		0x13970000

#define EXYNOS4_PA_PCM0			0x03840000
#define EXYNOS4_PA_PCM1			0x13980000
#define EXYNOS4_PA_PCM2			0x13990000

#define EXYNOS4_PA_SROM_BANK(x)		(0x04000000 + ((x) * 0x01000000))

#define EXYNOS4_PA_ONENAND		0x0C000000
#define EXYNOS4_PA_ONENAND_DMA		0x0C600000

#define EXYNOS4_PA_CHIPID		0x10000000

#define EXYNOS4_PA_SYSCON		0x10010000
#define EXYNOS4_PA_PMU			0x10020000
#define EXYNOS4_PA_CMU			0x10030000

#define EXYNOS4_PA_SYSTIMER		0x10050000
#define EXYNOS4_PA_WATCHDOG		0x10060000
#define EXYNOS4_PA_RTC			0x10070000

#define EXYNOS4_PA_KEYPAD		0x100A0000

#define EXYNOS4_PA_CEC			0x100B0000

#define EXYNOS4_PA_TMU			0x100C0000

#define EXYNOS4_PA_DMC0			0x10400000
#define EXYNOS4_PA_DMC1			0x10410000

#define EXYNOS4_PA_COMBINER		0x10440000

#define EXYNOS4_PA_IEM			0x10460000

#define EXYNOS4_PA_GIC_CPU		0x10480000
#define EXYNOS4_PA_GIC_DIST		0x10490000

#define EXYNOS4_PA_COREPERI		0x10500000
#define EXYNOS4_PA_TWD			0x10500600
#define EXYNOS4_PA_L2CC			0x10502000

#define EXYNOS4_PA_C2C			0x10540000
#define EXYNOS4_PA_C2C_CP		0x10580000

#define EXYNOS4_PA_DMC0_4212		0x10600000
#define EXYNOS4_PA_DMC1_4212		0x10610000

#define EXYNOS4_PA_PPMU_DMC0		0x106A0000
#define EXYNOS4_PA_PPMU_DMC1		0x106B0000
#define EXYNOS4_PA_PPMU_CPU		0x106C0000

#define EXYNOS4_PA_S_MDMA0		0x10800000
#define EXYNOS4_PA_NS_MDMA0		0x10810000
#define EXYNOS4_PA_ACE			0x10830000
#define EXYNOS4_PA_S_MDMA1		0x12840000
#define EXYNOS4_PA_NS_MDMA1		0x12850000
#define EXYNOS4_PA_PDMA0		0x12680000
#define EXYNOS4_PA_PDMA1		0x12690000

#define EXYNOS4_PA_SYSMMU_G2D_ACP	0x10A40000
#define EXYNOS4_PA_SYSMMU_SSS		0x10A50000
#define EXYNOS4_PA_SYSMMU_FIMC0		0x11A20000
#define EXYNOS4_PA_SYSMMU_FIMC1		0x11A30000
#define EXYNOS4_PA_SYSMMU_FIMC2		0x11A40000
#define EXYNOS4_PA_SYSMMU_FIMC3		0x11A50000
#define EXYNOS4_PA_SYSMMU_JPEG		0x11A60000
#define EXYNOS4_PA_DSIM0		0x11C80000
#define EXYNOS4_PA_DSIM1		0x12080000
#define EXYNOS4_PA_SYSMMU_FIMD0		0x11E20000
#define EXYNOS4_PA_SYSMMU_FIMD1		0x12220000
#define EXYNOS4_PA_SYSMMU_ISP		0x12260000
#define EXYNOS4_PA_SYSMMU_DRC		0x12270000
#define EXYNOS4_PA_SYSMMU_FD		0x122A0000
#define EXYNOS4_PA_SYSMMU_ISPCPU	0x122B0000
#define EXYNOS4_PA_SYSMMU_FIMC_LITE0	0x123B0000
#define EXYNOS4_PA_SYSMMU_FIMC_LITE1	0x123C0000
#define EXYNOS4_PA_SYSMMU_PCIe		0x12620000
#define EXYNOS4_PA_SYSMMU_GPS		0x12730000
#define EXYNOS4_PA_SYSMMU_G2D		0x12A20000
#define EXYNOS4_PA_SYSMMU_ROTATOR	0x12A30000
#define EXYNOS4_PA_SYSMMU_MDMA2		0x12A40000
#define EXYNOS4_PA_SYSMMU_TV		0x12E20000
#define EXYNOS4_PA_SYSMMU_MFC_L		0x13620000
#define EXYNOS4_PA_SYSMMU_MFC_R		0x13630000

#define EXYNOS4_PA_GPIO1		0x11400000
#define EXYNOS4_PA_GPIO2		0x11000000
#define EXYNOS4_PA_GPIO3		0x03860000
#define EXYNOS4_PA_GPIO4		0x106E0000

#define EXYNOS4_PA_MIPI_CSIS0		0x11880000
#define EXYNOS4_PA_MIPI_CSIS1		0x11890000

#define EXYNOS4_PA_FIMD0		0x11C00000
#define EXYNOS4_PA_FIMD1		0x12000000
#define EXYNOS4_PA_FIMC_IS		0x12000000

#define EXYNOS4_PA_FIMC_LITE0		0x12390000
#define EXYNOS4_PA_FIMC_LITE1		0x123A0000

#define EXYNOS4_PA_HSOTG		0x12480000
#define EXYNOS4_PA_HSPHY		0x125B0000

#define EXYNOS4_PA_HSMMC(x)		(0x12510000 + ((x) * 0x10000))
#define EXYNOS4_PA_DWMCI		0x12550000

#define EXYNOS4_PA_MIPIHSI		0x12560000

#define EXYNOS4_PA_SATA			0x12560000
#define EXYNOS4_PA_SATAPHY		0x125D0000
#define EXYNOS4_PA_SATAPHY_CTRL		0x126B0000

#define EXYNOS4_PA_SROMC		0x12570000

#define EXYNOS4_PA_EHCI			0x12580000
#define EXYNOS4_PA_OHCI			0x12590000
#define EXYNOS4_PA_HSPHY		0x125B0000

#define EXYNOS4412_PA_ADC		0x126C0000

#define EXYNOS4_PA_GPS			0x12700000

#define EXYNOS4_PA_FIMG2D		0x10800000

#define EXYNOS4_PA_ROTATOR		0x12810000

#define EXYNOS4_PA_VP			0x12C00000
#define EXYNOS4_PA_MIXER		0x12C10000
#define EXYNOS4_PA_TVENC		0x12C20000
#define EXYNOS4_PA_SDO			0x12C20000
#define EXYNOS4_PA_HDMI			0x12D00000

#define EXYNOS4_PA_G3D			0x13000000

#define EXYNOS4_PA_MFC			0x13400000

#define EXYNOS4_PA_UART			0x13800000

#define EXYNOS4_PA_IIC(x)		(0x13860000 + ((x) * 0x10000))

#define EXYNOS4_I2C_HDMI_PHY		0x138E0000
#define EXYNOS4_PA_IIC_HDMIPHY		0x138E0000

#define EXYNOS4210_PA_ADC		0x13910000
#define EXYNOS4210_PA_ADC1		0x13911000

#define EXYNOS4_PA_SPI0			0x13920000
#define EXYNOS4_PA_SPI1			0x13930000
#define EXYNOS4_PA_SPI2			0x13940000

#define EXYNOS4_PA_AC97			0x139A0000

#define EXYNOS4_PA_SPDIF		0x139B0000

#define EXYNOS4_PA_TIMER		0x139D0000

#define EXYNOS4_PA_SDRAM		0x40000000

/* Compatibiltiy Defines */

#define EXYNOS_PA_DWMCI			EXYNOS4_PA_DWMCI

#define EXYNOS_PA_AUDSS			EXYNOS4_PA_AUDSS
#define EXYNOS_PA_I2S0			EXYNOS4_PA_I2S0
#define EXYNOS_PA_I2S1			EXYNOS4_PA_I2S1
#define EXYNOS_PA_I2S2			EXYNOS4_PA_I2S2

#define EXYNOS_PA_PCM0			EXYNOS4_PA_PCM0
#define EXYNOS_PA_PCM1			EXYNOS4_PA_PCM1
#define EXYNOS_PA_PCM2			EXYNOS4_PA_PCM2

#define EXYNOS_PA_SPI0			EXYNOS4_PA_SPI0
#define EXYNOS_PA_SPI1			EXYNOS4_PA_SPI1
#define EXYNOS_PA_SPI2			EXYNOS4_PA_SPI2

#define EXYNOS_PA_AC97			EXYNOS4_PA_AC97

#define EXYNOS_PA_SPDIF			EXYNOS4_PA_SPDIF

#define EXYNOS_PA_FIMC_LITE0		EXYNOS4_PA_FIMC_LITE0
#define EXYNOS_PA_FIMC_LITE1		EXYNOS4_PA_FIMC_LITE1

#define EXYNOS_PA_ROTATOR		EXYNOS4_PA_ROTATOR

#define EXYNOS_PA_C2C			EXYNOS4_PA_C2C
#define EXYNOS_PA_C2C_CP		EXYNOS4_PA_C2C_CP

#define EXYNOS_PA_MIPIHSI		EXYNOS4_PA_MIPIHSI

#define S3C_PA_HSMMC0			EXYNOS4_PA_HSMMC(0)
#define S3C_PA_HSMMC1			EXYNOS4_PA_HSMMC(1)
#define S3C_PA_HSMMC2			EXYNOS4_PA_HSMMC(2)
#define S3C_PA_HSMMC3			EXYNOS4_PA_HSMMC(3)
#define S3C_PA_IIC			EXYNOS4_PA_IIC(0)
#define S3C_PA_IIC1			EXYNOS4_PA_IIC(1)
#define S3C_PA_IIC2			EXYNOS4_PA_IIC(2)
#define S3C_PA_IIC3			EXYNOS4_PA_IIC(3)
#define S3C_PA_IIC4			EXYNOS4_PA_IIC(4)
#define S3C_PA_IIC5			EXYNOS4_PA_IIC(5)
#define S3C_PA_IIC6			EXYNOS4_PA_IIC(6)
#define S3C_PA_IIC7			EXYNOS4_PA_IIC(7)
#if defined(CONFIG_CPU_EXYNOS4210)
#define SAMSUNG_PA_ADC			EXYNOS4210_PA_ADC
#define SAMSUNG_PA_ADC1			EXYNOS4210_PA_ADC1
#elif defined(CONFIG_CPU_EXYNOS4412)
#define SAMSUNG_PA_ADC			EXYNOS4412_PA_ADC
#endif
#define S3C_PA_RTC			EXYNOS4_PA_RTC
#define S3C_PA_WDT			EXYNOS4_PA_WATCHDOG

#define S5P_PA_CHIPID			EXYNOS4_PA_CHIPID
#define S5P_PA_FIMC0			EXYNOS4_PA_FIMC0
#define S5P_PA_FIMC1			EXYNOS4_PA_FIMC1
#define S5P_PA_FIMC2			EXYNOS4_PA_FIMC2
#define S5P_PA_FIMC3			EXYNOS4_PA_FIMC3
#define S5P_PA_MIPI_CSIS0		EXYNOS4_PA_MIPI_CSIS0
#define S5P_PA_MIPI_CSIS1		EXYNOS4_PA_MIPI_CSIS1
#define S5P_PA_FIMD0			EXYNOS4_PA_FIMD0
#define S5P_PA_FIMD1			EXYNOS4_PA_FIMD1
#define S5P_PA_FIMG2D			EXYNOS4_PA_FIMG2D
#define S5P_PA_ONENAND			EXYNOS4_PA_ONENAND
#define S5P_PA_ONENAND_DMA		EXYNOS4_PA_ONENAND_DMA
#define S5P_PA_SDRAM			EXYNOS4_PA_SDRAM
#define S5P_PA_SROMC			EXYNOS4_PA_SROMC
#define S5P_PA_MFC			EXYNOS4_PA_MFC
#define S5P_PA_SYSCON			EXYNOS4_PA_SYSCON
#define S5P_PA_TIMER			EXYNOS4_PA_TIMER
#define S5P_PA_HSOTG			EXYNOS4_PA_HSOTG
#define S5P_PA_HSPHY			EXYNOS4_PA_HSPHY
#define S5P_PA_EHCI			EXYNOS4_PA_EHCI
#define S5P_PA_OHCI			EXYNOS4_PA_OHCI
#define S5P_PA_JPEG			EXYNOS4_PA_JPEG
#define S5P_PA_TMU			EXYNOS4_PA_TMU
#define S5P_PA_DSIM0			EXYNOS4_PA_DSIM0
#define S5P_PA_DSIM1			EXYNOS4_PA_DSIM1

#define SAMSUNG_PA_KEYPAD		EXYNOS4_PA_KEYPAD

#define S5P_PA_HDMI_CEC			EXYNOS4_PA_CEC
#define S5P_SZ_HDMI_CEC			SZ_4K

#define S5P_PA_VP			EXYNOS4_PA_VP
#define S5P_PA_MIXER			EXYNOS4_PA_MIXER
#define S5P_PA_TVENC			EXYNOS4_PA_TVENC
#define S5P_PA_SDO			EXYNOS4_PA_SDO
#define S5P_PA_HDMI			EXYNOS4_PA_HDMI
#define S5P_I2C_HDMI_PHY		EXYNOS4_I2C_HDMI_PHY
#define S5P_PA_IIC_HDMIPHY		EXYNOS4_PA_IIC_HDMIPHY
#define S5P_SZ_VP			SZ_64K
#define S5P_SZ_MIXER			SZ_64K
#define S5P_SZ_TVENC			SZ_64K
#define S5P_SZ_SDO			SZ_64K
#define S5P_SZ_HDMI			SZ_1M
#define S5P_I2C_HDMI_SZ_PHY		SZ_1K
#define S5P_SZ_IIC_HDMIPHY		SZ_1K
#define S5P_PA_ACE			EXYNOS4_PA_ACE

#define S5P_PA_MDMA0			EXYNOS4_PA_NS_MDMA0
#define S5P_PA_MDMA1			EXYNOS4_PA_NS_MDMA1
#define S5P_PA_PDMA0			EXYNOS4_PA_PDMA0
#define S5P_PA_PDMA1			EXYNOS4_PA_PDMA1

/* UART */

#define S3C_VA_UARTx(x)			(S3C_VA_UART + ((x) * S3C_UART_OFFSET))

#define S3C_PA_UART			EXYNOS4_PA_UART

#define S5P_PA_UART(x)			(S3C_PA_UART + ((x) * S3C_UART_OFFSET))
#define S5P_PA_UART0			S5P_PA_UART(0)
#define S5P_PA_UART1			S5P_PA_UART(1)
#define S5P_PA_UART2			S5P_PA_UART(2)
#define S5P_PA_UART3			S5P_PA_UART(3)
#define S5P_PA_UART4			S5P_PA_UART(4)

#define S5P_SZ_UART			SZ_256

#endif /* __ASM_ARCH_MAP_EXYNOS4_H */