#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Python script to list a udemy.com courses in an account"""
import logging
import colorlog

from .udemy_list import udemy_list

__all__ = ['udemy_list']
__title__ = 'udemy_list'
__author__ = 'Waqas Rana'
__license__ = 'Unlicense'
__copyright__ = 'Copyright 2017 Waqas Rana'


handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    '%(log_color)s[%(levelname)s-%(lineno)d] %(message)s'))

logger = colorlog.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(level=logging.INFO)
