import redis

def get_redis_data():
    try:
        r = redis.Redis(host='82.157.60.174', port=6379, password='2024111', decode_responses=True)
        r.ping()
        data = r.hgetall('monero')
        return data
    except redis.exceptions.ConnectionError as e:
        print(f"Could not connect to Redis: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def get_monero_data():
    redis_data = get_redis_data()
    if redis_data:
        return {
            'hash': redis_data.get('hash'),
            'height': int(redis_data.get('height', 0)),
            'cumulative_difficulty': int(redis_data.get('cumulative_difficulty', 0)),
            'cumulative_difficulty_top64': int(redis_data.get('cumulative_difficulty_top64', 0)),
        }
    # Fallback to default values if Redis is not available
    return {
        'hash': "418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3",
        'height': 2936891,
        'cumulative_difficulty': 1156656256623,
        'cumulative_difficulty_top64': 0,
    }

if __name__ == '__main__':
    monero_data = get_monero_data()
    if monero_data:
        print(monero_data)
