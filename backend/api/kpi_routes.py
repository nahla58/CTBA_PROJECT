"""
KPI and Analytics Endpoints for Analyst Performance Tracking
"""
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from fastapi import APIRouter, Query, HTTPException
from database import get_db_connection

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/kpi", tags=["kpi"])


@router.get("/analyst-performance")
async def get_analyst_performance(
    period: str = Query("month", description="Period: day, week, month, year")
):
    """Get analyst performance metrics"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Calculate date range
        now = datetime.now()
        if period == "day":
            start_date = now - timedelta(days=1)
        elif period == "week":
            start_date = now - timedelta(weeks=1)
        elif period == "year":
            start_date = now - timedelta(days=365)
        else:  # month
            start_date = now - timedelta(days=30)
        
        # Format date for SQLite (YYYY-MM-DD HH:MM:SS)
        start_date_str = start_date.strftime('%Y-%m-%d %H:%M:%S')
        
        # Get analyst actions (excluding automatic actions)
        cursor.execute('''
            SELECT 
                analyst,
                action,
                COUNT(*) as count
            FROM cve_actions
            WHERE action_date >= ?
            AND (comments IS NULL OR comments NOT LIKE 'Auto-%')
            GROUP BY analyst, action
        ''', (start_date_str,))
        
        actions = cursor.fetchall()
        
        # Get last action dates for each analyst
        cursor = conn.cursor()
        cursor.execute('''
            SELECT analyst, MAX(action_date) as last_action
            FROM cve_actions
            GROUP BY analyst
        ''')
        last_actions = {row['analyst']: row['last_action'] for row in cursor.fetchall()}
        
        conn.close()
        
        # Aggregate by analyst
        analysts = {}
        for row in actions:
            analyst = row['analyst']
            action = row['action']
            count = row['count']
            
            if analyst not in analysts:
                analysts[analyst] = {
                    'analyst': analyst,
                    'accepted': 0,
                    'rejected': 0,
                    'deferred': 0,
                    'total_actions': 0,
                    'acceptance_rate': 0,
                    'avg_actions_per_day': 0,
                    'last_action_date': last_actions.get(analyst)
                }
            
            if action == 'ACCEPTED':
                analysts[analyst]['accepted'] += count
            elif action == 'REJECTED':
                analysts[analyst]['rejected'] += count
            elif action == 'DEFERRED':
                analysts[analyst]['deferred'] += count
            
            analysts[analyst]['total_actions'] += count
        
        # Calculate rates and averages
        days_in_period = (now - start_date).days or 1
        for analyst_data in analysts.values():
            total = analyst_data['total_actions']
            if total > 0:
                analyst_data['acceptance_rate'] = round((analyst_data['accepted'] / total) * 100, 1)
            analyst_data['avg_actions_per_day'] = round(total / days_in_period, 1)
        
        return {
            'success': True,
            'period': period,
            'analysts': list(analysts.values())
        }
        
    except Exception as e:
        logger.error(f"Error fetching analyst performance: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/action-statistics")
async def get_action_statistics(
    period: str = Query("month", description="Period: day, week, month, year")
):
    """Get action statistics (accepted, rejected, deferred)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Calculate date range
        now = datetime.now()
        if period == "day":
            start_date = now - timedelta(days=1)
        elif period == "week":
            start_date = now - timedelta(weeks=1)
        elif period == "year":
            start_date = now - timedelta(days=365)
        else:  # month
            start_date = now - timedelta(days=30)
        
        # Format date for SQLite (YYYY-MM-DD HH:MM:SS)
        start_date_str = start_date.strftime('%Y-%m-%d %H:%M:%S')
        
        # Get action counts (excluding automatic actions)
        cursor.execute('''
            SELECT 
                action,
                COUNT(*) as count
            FROM cve_actions
            WHERE action_date >= ?
            AND (comments IS NULL OR comments NOT LIKE 'Auto-%')
            GROUP BY action
        ''', (start_date_str,))
        
        actions = cursor.fetchall()
        conn.close()
        
        stats = {
            'total_accepted': 0,
            'total_rejected': 0,
            'total_deferred': 0,
            'total_reviewed': 0,
            'acceptance_rate': 0,
            'severity_distribution': {}
        }
        
        for row in actions:
            action = row['action']
            count = row['count']
            
            if action == 'ACCEPTED':
                stats['total_accepted'] = count
            elif action == 'REJECTED':
                stats['total_rejected'] = count
            elif action == 'DEFERRED':
                stats['total_deferred'] = count
            
            stats['total_reviewed'] += count
        
        # Calculate acceptance rate
        if stats['total_reviewed'] > 0:
            stats['acceptance_rate'] = round((stats['total_accepted'] / stats['total_reviewed']) * 100, 1)
        
        return stats
        
    except Exception as e:
        logger.error(f"Error fetching action statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/action-trends")
async def get_action_trends(
    days: int = Query(30, ge=1, le=365, description="Number of days for trend")
):
    """Get action trends over time"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        start_date = datetime.now() - timedelta(days=days)
        start_date_str = start_date.strftime('%Y-%m-%d %H:%M:%S')
        
        # Get daily action counts (excluding automatic actions)
        cursor.execute('''
            SELECT 
                DATE(action_date) as date,
                action,
                COUNT(*) as count
            FROM cve_actions
            WHERE action_date >= ?
            AND (comments IS NULL OR comments NOT LIKE 'Auto-%')
            GROUP BY DATE(action_date), action
            ORDER BY DATE(action_date)
        ''', (start_date_str,))
        
        actions = cursor.fetchall()
        conn.close()
        
        # Organize by date
        trends = {}
        for row in actions:
            date = row['date']
            action = row['action']
            count = row['count']
            
            if date not in trends:
                trends[date] = {
                    'date': date,
                    'accepted': 0,
                    'rejected': 0,
                    'deferred': 0,
                    'total': 0
                }
            
            # Use lowercase for frontend compatibility
            if action == 'ACCEPTED':
                trends[date]['accepted'] = count
            elif action == 'REJECTED':
                trends[date]['rejected'] = count
            elif action == 'DEFERRED':
                trends[date]['deferred'] = count
            
            trends[date]['total'] += count
        
        return {
            'success': True,
            'days': days,
            'trends': list(trends.values())
        }
        
    except Exception as e:
        logger.error(f"Error fetching action trends: {e}")
        raise HTTPException(status_code=500, detail=str(e))
