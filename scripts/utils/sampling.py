import random

class ReservoirSampler:
    """
    Reservoir sampling implementation for sampling from a stream of items.
    Maintains a fixed-size sample as items are added.
    """
    def __init__(self, size: int, seed: int = None):
        self.size = size
        self.reservoir = []
        self.count = 0
        self.rng = random.Random(seed) if seed is not None else random

    def add(self, item):
        """
        Add an item to the reservoir sample.
        """
        self.count += 1
        if len(self.reservoir) < self.size:
            self.reservoir.append(item)
        else:
            j = self.rng.randint(0, self.count - 1)
            if j < self.size:
                self.reservoir[j] = item

    def get_sample(self):
        """
        Get the current reservoir sample.
        """
        return self.reservoir.copy()

    def __len__(self):
        return len(self.reservoir)